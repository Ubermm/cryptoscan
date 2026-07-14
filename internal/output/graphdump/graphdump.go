// Package graphdump provides deterministic serialization of a *graph.Graph to
// machine-readable formats: a stable JSON object (WriteJSON) and Graphviz DOT
// (WriteDOT).
//
// Both writers are projections of the graph (DESIGN.md principle 2: the graph is
// primary, everything else is a view of it). They are pure output — they never
// mutate the graph — and are deterministic: nodes are emitted sorted by ID and
// edges sorted by (type, from, to), exactly as graph.Nodes()/graph.Edges()
// return them, and every map is rendered with sorted keys. Neither writer panics
// on any graph, including an empty graph or one whose node attributes contain
// quotes, backslashes, or newlines.
//
// The package depends only on the standard library and internal/graph. It is
// distinct from the CycloneDX CBOM emitter: this is a faithful dump of the graph
// model itself, not a standards-native bill of materials.
package graphdump
