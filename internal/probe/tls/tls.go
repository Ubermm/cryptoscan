// Package tls is the Phase 2 network prober for TLS endpoints. It implements the
// probe.Prober contract (Scheme "tls") and is registered into the process-wide
// probe registry from init, so the CLI's `cryptoscan probe` drives it through
// the single batch driver probe.Run.
//
// For one host:port it observes what a server presents on the wire — it never
// validates trust (InsecureSkipVerify is deliberate: we RECORD the chain and
// parameters, we do not judge them):
//
//   - a primary handshake with a default client config + SNI + ALPN (h2,
//     http/1.1), recording the negotiated version, cipher suite (IANA name),
//     ALPN result, and the presented certificate chain (raw DER);
//   - a per-version enumeration (TLS 1.0–1.3, one MinVersion==MaxVersion
//     handshake each) yielding protocols_supported; and
//   - a hybrid post-quantum probe that offers ONLY the X25519MLKEM768 group,
//     yielding pqc_hybrid_kex.
//
// Everything is deterministic and provable (principle 1): the tls_endpoint
// finding and every graph node trace to a handshake with Source "probe" and
// Path host:port (DESIGN.md §1 network probe contract). The presented chain is
// parsed with the SAME strict code path as the filesystem scanner
// (internal/scan/certs), so a certificate seen at an endpoint and on disk
// resolves to ONE graph node — the cross-surface entity-resolution promise.
//
// Connections are opened through a single shared netutil.Dialer, so the
// connection-layer rate limit is enforced across every target and every
// per-version handshake of a run (one target performs ~6 handshakes, which is
// why rate limiting belongs at the connection layer, not the target layer). The
// package never panics; an unreachable target is returned as an error and
// probe.Run keeps the batch going.
package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/cryptoscan/cryptoscan/internal/graph"
	"github.com/cryptoscan/cryptoscan/internal/probe"
	"github.com/cryptoscan/cryptoscan/internal/probe/netutil"
	"github.com/cryptoscan/cryptoscan/internal/scan/certs"
)

// init registers the default TLS prober so a blank import (from the CLI) makes
// it available to probe.All(). Registration is order-independent.
func init() { probe.Register(New()) }

// defaultALPN is the ALPN protocol list offered on every handshake (DESIGN.md:
// "ALPN offering h2/http1.1").
var defaultALPN = []string{"h2", "http/1.1"}

// enumVersions is the ordered TLS version table for per-version enumeration. The
// names are the DESIGN.md §2 spellings, emitted in ascending version order.
var enumVersions = []struct {
	version uint16
	name    string
}{
	{tls.VersionTLS10, "TLSv1"},
	{tls.VersionTLS11, "TLSv1.1"},
	{tls.VersionTLS12, "TLSv1.2"},
	{tls.VersionTLS13, "TLSv1.3"},
}

// Prober is the TLS implementation of probe.Prober. The zero value is usable
// (netutil defaults, default ALPN); the CLI may set Net/ALPN before the first
// Probe. It is safe for concurrent use across targets: a single shared Dialer is
// created once and reused, so the connection rate limit spans the whole run.
type Prober struct {
	// Net configures dialing, the per-connection timeout, and the shared
	// connection rate limit (netutil). The zero value uses netutil defaults.
	Net netutil.Options
	// ALPN is the protocol list offered via the TLS ALPN extension on the
	// primary handshake. Nil selects defaultALPN; an explicitly empty (non-nil)
	// slice offers no ALPN. Set it before the first Probe.
	ALPN []string

	once   sync.Once
	dialer *netutil.Dialer
}

// New returns a ready-to-use TLS prober with netutil defaults.
func New() *Prober { return &Prober{} }

// Scheme implements probe.Prober.
func (p *Prober) Scheme() string { return "tls" }

// dial lazily builds (once) the shared Dialer carrying the connection rate
// limiter, so every target and handshake of a run draws on one rate budget.
func (p *Prober) dial() *netutil.Dialer {
	p.once.Do(func() { p.dialer = p.Net.NewDialer() })
	return p.dialer
}

// alpn returns the configured ALPN list, defaulting when nil.
func (p *Prober) alpn() []string {
	if p.ALPN == nil {
		return defaultALPN
	}
	return p.ALPN
}

// Probe implements probe.Prober. It observes t, populates g with the Endpoint
// node and the certificate subgraph (terminates_tls_for for the leaf, signs_with
// per cert, issued_by per chain link), and returns the single tls_endpoint
// finding (DESIGN.md §1). An unreachable target (dial failure) is returned as a
// wrapped error with NO graph writes; a reachable port that speaks no TLS is
// likewise returned as an error so probe.Run records it and moves on.
func (p *Prober) Probe(ctx context.Context, t probe.Target, g *graph.Graph) ([]probe.Finding, error) {
	obs, err := p.observe(ctx, t)
	if err != nil {
		return nil, err
	}
	if !obs.handshakeOK && len(obs.protocols) == 0 {
		return nil, fmt.Errorf("tls: %s: reachable but completed no TLS handshake", t.Addr())
	}
	if err := populate(g, t, obs); err != nil {
		return nil, fmt.Errorf("tls: %s: populating graph: %w", t.Addr(), err)
	}
	return []probe.Finding{obs.finding(t)}, nil
}

// observation is everything a single Probe learned from the wire.
type observation struct {
	handshakeOK bool     // primary (default-config) handshake completed
	negotiated  string   // primary negotiated version, DESIGN.md spelling
	cipher      string   // primary negotiated cipher-suite IANA name
	alpn        string   // primary ALPN selection ("" if none)
	protocols   []string // versions that completed a pinned handshake, ascending
	pqcHybrid   bool     // server completed a handshake with only X25519MLKEM768
	certDER     [][]byte // presented chain as raw DER, leaf first
}

// observe performs the primary handshake, the per-version enumeration, and the
// hybrid PQC probe against t. It returns an error only for a dial failure
// (endpoint unreachable); a reachable endpoint that refuses TLS yields a
// non-error observation with handshakeOK false and no supported protocols.
func (p *Prober) observe(ctx context.Context, t probe.Target) (observation, error) {
	addr := t.Addr()
	host := t.Host
	dialer := p.dial()
	alpn := p.alpn()
	timeout := p.Net.Normalize().Timeout

	var obs observation

	// Primary handshake: default client config, SNI, ALPN. Distinguish an
	// unreachable endpoint (dial failure) from a reachable non-TLS port.
	primary := handshake(ctx, dialer, addr, host, alpn, timeout, 0, 0, nil)
	if primary.dialErr != nil {
		return observation{}, fmt.Errorf("tls: dial %s: %w", addr, primary.dialErr)
	}
	if primary.state != nil {
		st := primary.state
		obs.handshakeOK = true
		obs.negotiated = protoName(st.Version)
		obs.cipher = tls.CipherSuiteName(st.CipherSuite)
		obs.alpn = st.NegotiatedProtocol
		for _, c := range st.PeerCertificates {
			obs.certDER = append(obs.certDER, c.Raw)
		}
	}

	// Version enumeration: one pinned handshake per version. Any failure (dial,
	// alert, timeout) means "not supported" for that version. If the primary
	// handshake produced no chain (e.g. the client default min-version refused
	// a legacy-only server), capture the chain from the first version that does.
	for _, ev := range enumVersions {
		hs := handshake(ctx, dialer, addr, host, alpn, timeout, ev.version, ev.version, nil)
		if hs.state == nil {
			continue
		}
		obs.protocols = append(obs.protocols, ev.name)
		if len(obs.certDER) == 0 {
			for _, c := range hs.state.PeerCertificates {
				obs.certDER = append(obs.certDER, c.Raw)
			}
		}
	}

	// Hybrid PQC probe: offer ONLY X25519MLKEM768 (TLS 1.3). A successful
	// handshake proves the server accepts that group as the sole offer.
	pqc := handshake(ctx, dialer, addr, host, alpn, timeout, tls.VersionTLS13, tls.VersionTLS13, []tls.CurveID{tls.X25519MLKEM768})
	if pqc.state != nil {
		obs.pqcHybrid = true
	}

	return obs, nil
}

// finding projects the observation into the tls_endpoint finding (DESIGN.md §1).
// protocols_supported is always a non-nil slice; peer_certs is the chain length.
func (o observation) finding(t probe.Target) probe.Finding {
	protos := o.protocols
	if protos == nil {
		protos = []string{}
	}
	return probe.Finding{
		Class: probe.ClassTLSEndpoint,
		Path:  t.Addr(),
		Attrs: map[string]any{
			"negotiated_protocol":     o.negotiated,
			"negotiated_cipher_suite": o.cipher,
			"alpn":                    o.alpn,
			"protocols_supported":     protos,
			"pqc_hybrid_kex":          o.pqcHybrid,
			"peer_certs":              len(o.certDER),
		},
		Provenance: []graph.Provenance{prov(t)},
	}
}

// prov is the single provenance record shared by this target's finding, nodes,
// and edges (Source probe, Location host:port).
func prov(t probe.Target) graph.Provenance {
	return graph.Provenance{Source: graph.SourceProbe, Location: t.Addr(), Detail: "tls handshake"}
}

// populate projects the observation into g per the DESIGN.md §1 network probe
// graph contract: one Endpoint node per host:port; the leaf certificate gets a
// terminates_tls_for edge to the Endpoint; every chain member gets signs_with
// (via the shared certs code path) and issued_by. Certificate and Key nodes
// reuse the fs identity keys, so a cert seen here and on disk is ONE node.
func populate(g *graph.Graph, t probe.Target, obs observation) error {
	pv := prov(t)

	epID, err := graph.EndpointNodeID(t.Host, t.Port)
	if err != nil {
		return err
	}
	ep := &graph.EndpointNode{Host: t.Host, Port: t.Port, Protocols: obs.protocols}
	if obs.cipher != "" {
		ep.CipherSuites = []string{obs.cipher}
	}
	if obs.alpn != "" {
		ep.ALPN = []string{obs.alpn}
	}
	ep.NodeID = epID
	ep.AddProvenance(pv)
	if _, err := g.UpsertNode(ep); err != nil {
		return err
	}

	// Parse the chain once with the strict fs code path and wire the nodes.
	chain := make([]*certs.ObservedCert, 0, len(obs.certDER))
	for i, der := range obs.certDER {
		oc, err := certs.ParseObservedCert(der)
		if err != nil {
			continue // malformed chain member: skip, never fatal
		}
		certID, _, err := certs.UpsertCertGraph(g, oc, pv)
		if err != nil {
			continue
		}
		chain = append(chain, oc)
		if i == 0 {
			// The leaf (chain index 0) terminates TLS for the endpoint.
			_, _ = g.AddEdge(graph.Edge{Type: graph.EdgeTerminatesTLSFor, From: certID, To: epID, Provenance: []graph.Provenance{pv}})
		}
	}
	certs.LinkChainIssuers(g, chain, pv)
	return nil
}

// hsResult is the outcome of one handshake attempt, separating a TCP-level dial
// failure (endpoint unreachable) from a TLS handshake failure (refused/alert).
type hsResult struct {
	state   *tls.ConnectionState
	dialErr error
	hsErr   error
}

// handshake dials addr through the shared Dialer and attempts a TLS handshake
// with the given SNI, ALPN, version pins, and curve preferences, then closes the
// connection. minV/maxV of 0 select the client defaults; curves of nil selects
// the client defaults. It never panics; the timeout bounds both the dial (via
// the Dialer) and the handshake (via a derived context).
func handshake(ctx context.Context, dialer *netutil.Dialer, addr, host string, alpn []string, timeout time.Duration, minV, maxV uint16, curves []tls.CurveID) hsResult {
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return hsResult{dialErr: err}
	}
	defer func() { _ = raw.Close() }()

	hctx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		hctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // we RECORD the presented chain, we do not validate trust (DESIGN.md §1)
		ServerName:         host,
		NextProtos:         alpn,
	}
	if minV != 0 {
		cfg.MinVersion = minV
	}
	if maxV != 0 {
		cfg.MaxVersion = maxV
	}
	if curves != nil {
		cfg.CurvePreferences = curves
	}

	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(hctx); err != nil {
		return hsResult{hsErr: err}
	}
	st := conn.ConnectionState()
	return hsResult{state: &st}
}

// protoName maps a negotiated TLS version to its DESIGN.md §2 spelling; an
// unknown version yields "".
func protoName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return ""
	}
}
