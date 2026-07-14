package graph

// ResolveReferences performs the cross-scanner entity-resolution join described
// in DESIGN.md §1. Server-config scanners emit `references` edges from a
// ConfigFile node to the ConfigFile node of a referenced path (e.g. an nginx
// ssl_certificate directive). Filesystem scanners independently emit `stored_in`
// edges from Certificate/Key nodes to the file node they physically live in.
// Because both scanners anchor file node IDs at the same cleaned absolute path,
// a referenced file and the file an asset is stored in resolve to the SAME node.
//
// For every `references` edge ConfigFile→FileNode, this pass finds each
// Certificate and Key node with a `stored_in` edge to that same FileNode and
// adds a `references` edge ConfigFile→Certificate (and ConfigFile→Key for key
// references), copying the originating directive's provenance so the join stays
// provable (principle 1). References whose target file was never scanned — e.g.
// an sshd HostKey at /etc/ssh/ssh_host_rsa_key that does not exist in the tree —
// have no `stored_in` assets and are deliberately left as bare file references;
// nothing is guessed.
//
// The pass is idempotent: re-running it adds no new edges (AddEdge dedupes on the
// (Type, From, To) triple). It returns the number of resolved config→asset
// reference edges present in the graph after the join.
func (g *Graph) ResolveReferences() int {
	// Snapshot the relevant edges once. storedInByFile maps a file node ID to
	// the Certificate/Key node IDs physically stored in it; refEdges holds the
	// config→file references to resolve.
	storedInByFile := map[string][]string{}
	var refEdges []Edge
	for _, e := range g.Edges() {
		switch e.Type {
		case EdgeStoredIn:
			storedInByFile[e.To] = append(storedInByFile[e.To], e.From)
		case EdgeReferences:
			refEdges = append(refEdges, e)
		}
	}

	for _, ref := range refEdges {
		for _, assetID := range storedInByFile[ref.To] {
			n, ok := g.Node(assetID)
			if !ok {
				continue
			}
			if t := n.Type(); t != NodeCertificate && t != NodeKey {
				continue
			}
			// Provenance is copied from the config directive so the resolved
			// edge traces back to the exact line that referenced the file.
			_, _ = g.AddEdge(Edge{
				Type:       EdgeReferences,
				From:       ref.From,
				To:         assetID,
				Provenance: ref.Provenance,
			})
		}
	}

	// Count is derived from the final graph (not the number of AddEdge calls) so
	// it is stable across repeated invocations: every `references` edge whose
	// target is a Certificate or Key node is a resolved config→asset join.
	resolved := 0
	for _, e := range g.Edges() {
		if e.Type != EdgeReferences {
			continue
		}
		if n, ok := g.Node(e.To); ok {
			if t := n.Type(); t == NodeCertificate || t == NodeKey {
				resolved++
			}
		}
	}
	return resolved
}
