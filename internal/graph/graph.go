// Package graph is the primary data model for cryptoscan: a set of typed nodes
// (Certificate, Key, Endpoint, ...) connected by typed, directed edges. All
// findings, reports, and the CBOM are projections of this graph.
//
// The package depends only on the standard library and never panics on
// malformed input; every fallible operation returns an error (see CLAUDE.md and
// docs/DESIGN.md §1, which are binding).
package graph

import (
	"fmt"
	"sort"
)

// Graph holds nodes keyed by ID and edges keyed by their (Type, From, To)
// triple. Entity resolution happens on upsert: a node with an existing ID is
// merged, never duplicated.
//
// Graph is not safe for concurrent use; callers must synchronize externally.
type Graph struct {
	nodes map[string]Node
	edges map[string]*Edge
}

// New returns an empty, ready-to-use Graph.
func New() *Graph {
	return &Graph{
		nodes: make(map[string]Node),
		edges: make(map[string]*Edge),
	}
}

// UpsertNode inserts n, or if a node with the same ID already exists, merges
// n's attributes and provenance into it (DESIGN.md entity resolution). The
// resident node (the one now stored in the graph) is returned.
//
// It is an error for n to be nil, to have an empty ID, or to have a different
// NodeType than an existing node with the same ID.
func (g *Graph) UpsertNode(n Node) (Node, error) {
	if n == nil {
		return nil, fmt.Errorf("graph: cannot upsert nil node")
	}
	id := n.ID()
	if id == "" {
		return nil, fmt.Errorf("graph: cannot upsert node with empty ID")
	}

	existing, ok := g.nodes[id]
	if !ok {
		g.nodes[id] = n
		return n, nil
	}
	if existing.Type() != n.Type() {
		return nil, fmt.Errorf("graph: node ID %q already exists as %s, cannot upsert as %s",
			id, existing.Type(), n.Type())
	}
	if err := existing.mergeFrom(n); err != nil {
		return nil, err
	}
	return existing, nil
}

// Node returns the node with the given ID and whether it was found.
func (g *Graph) Node(id string) (Node, bool) {
	n, ok := g.nodes[id]
	return n, ok
}

// AddEdge inserts e, or if an identical (Type, From, To) edge already exists,
// unions e's provenance into it (dedupe). The resident edge is returned.
//
// It is an error for the edge Type to be unknown or for From/To to be empty.
// Endpoints are not required to already exist as nodes (edges may be added
// before their nodes during a scan).
func (g *Graph) AddEdge(e Edge) (*Edge, error) {
	if !e.Type.Valid() {
		return nil, fmt.Errorf("graph: unknown edge type %q", e.Type)
	}
	if e.From == "" || e.To == "" {
		return nil, fmt.Errorf("graph: edge %q requires non-empty From and To", e.Type)
	}

	k := e.key()
	if existing, ok := g.edges[k]; ok {
		existing.addProvenance(e.Provenance...)
		return existing, nil
	}

	stored := &Edge{
		Type: e.Type,
		From: e.From,
		To:   e.To,
	}
	stored.addProvenance(e.Provenance...)
	g.edges[k] = stored
	return stored, nil
}

// addProvenance appends records to an edge, unioning duplicates away.
func (e *Edge) addProvenance(ps ...Provenance) {
	for _, p := range ps {
		if !containsProv(e.Provenance, p) {
			e.Provenance = append(e.Provenance, p)
		}
	}
}

// Nodes returns all nodes sorted by ID, for deterministic output.
func (g *Graph) Nodes() []Node {
	out := make([]Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID() < out[j].ID()
	})
	return out
}

// Edges returns all edges sorted by (Type, From, To), for deterministic output.
func (g *Graph) Edges() []Edge {
	out := make([]Edge, 0, len(g.edges))
	for _, e := range g.edges {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out
}

// NodeCount returns the number of distinct nodes in the graph.
func (g *Graph) NodeCount() int { return len(g.nodes) }

// EdgeCount returns the number of distinct edges in the graph.
func (g *Graph) EdgeCount() int { return len(g.edges) }
