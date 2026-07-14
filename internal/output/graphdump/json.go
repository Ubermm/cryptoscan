package graphdump

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/Ubermm/cryptoscan/internal/graph"
)

// jsonNode is the stable on-disk shape of a graph node: its identity key, its
// NodeType, an attribute object (all node-specific fields, with sorted keys),
// and its provenance records. The attrs object mirrors the node struct's JSON
// encoding minus the id/provenance envelope, so it stays in sync with the graph
// model automatically.
type jsonNode struct {
	ID         string                     `json:"id"`
	Type       string                     `json:"type"`
	Attrs      map[string]json.RawMessage `json:"attrs"`
	Provenance []graph.Provenance         `json:"provenance"`
}

// jsonEdge is the stable on-disk shape of a graph edge.
type jsonEdge struct {
	Type       string             `json:"type"`
	From       string             `json:"from"`
	To         string             `json:"to"`
	Provenance []graph.Provenance `json:"provenance"`
}

// jsonDump is the top-level object: {nodes:[...], edges:[...]}.
type jsonDump struct {
	Nodes []jsonNode `json:"nodes"`
	Edges []jsonEdge `json:"edges"`
}

// WriteJSON writes g to w as a stable, pretty-printed JSON object of the form
// {"nodes":[...],"edges":[...]}.
//
// Each node is rendered as {id, type, attrs, provenance} where attrs holds the
// node's type-specific fields with sorted keys; each edge as
// {type, from, to, provenance}. Nodes are emitted sorted by ID and edges sorted
// by (type, from, to), so the output is byte-for-byte deterministic for a given
// graph. A trailing newline is written. The function does not panic on any
// graph, including an empty one (which yields empty nodes/edges arrays).
func WriteJSON(w io.Writer, g *graph.Graph) error {
	nodes := g.Nodes()
	edges := g.Edges()

	dump := jsonDump{
		Nodes: make([]jsonNode, 0, len(nodes)),
		Edges: make([]jsonEdge, 0, len(edges)),
	}

	for _, n := range nodes {
		jn, err := toJSONNode(n)
		if err != nil {
			return fmt.Errorf("graphdump: encoding node %q: %w", n.ID(), err)
		}
		dump.Nodes = append(dump.Nodes, jn)
	}

	for _, e := range edges {
		prov := e.Provenance
		if prov == nil {
			prov = []graph.Provenance{}
		}
		dump.Edges = append(dump.Edges, jsonEdge{
			Type:       string(e.Type),
			From:       e.From,
			To:         e.To,
			Provenance: prov,
		})
	}

	out, err := json.MarshalIndent(dump, "", "  ")
	if err != nil {
		return fmt.Errorf("graphdump: marshaling graph: %w", err)
	}
	out = append(out, '\n')
	if _, err := w.Write(out); err != nil {
		return fmt.Errorf("graphdump: writing graph JSON: %w", err)
	}
	return nil
}

// toJSONNode projects a graph.Node into its stable JSON shape. It marshals the
// concrete node struct, then lifts out the id/provenance envelope so the
// remaining fields become the sorted-key attrs object. This keeps attrs in lock
// step with the node struct definitions without a hand-maintained field switch.
func toJSONNode(n graph.Node) (jsonNode, error) {
	raw, err := json.Marshal(n)
	if err != nil {
		return jsonNode{}, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return jsonNode{}, err
	}
	delete(m, "id")
	delete(m, "provenance")

	prov := n.Provenance()
	if prov == nil {
		prov = []graph.Provenance{}
	}

	return jsonNode{
		ID:         n.ID(),
		Type:       string(n.Type()),
		Attrs:      m,
		Provenance: prov,
	}, nil
}
