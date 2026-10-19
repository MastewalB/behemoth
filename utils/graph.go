package utils

import "sort"

// KahnSort performs topological sorting on a given Directed Acyclic Graph.
// The graph map should have nodes as keys and their dependants as lists.
// For eg. If A and C depend on B,
// B: {A, C}
// Ties among nodes with in-degree zero at the same step are broken by name, ascending
func KahnSort(graph map[string][]string, less func(a, b string) bool) (order []string, cyclePath []string, ok bool) {

	// Collect every node
	allNodes := make(map[string]bool)
	for node, dependants := range graph {
		allNodes[node] = true
		for _, d := range dependants {
			allNodes[d] = true
		}
	}

	// Use len(allNodes) instead of N since some nodes might only be listed as dependants
	N := len(allNodes)
	indegree := make(map[string]int, N)
	for n := range allNodes {
		indegree[n] = 0
	}
	for _, dependants := range graph {
		for _, dep := range dependants {
			indegree[dep]++
		}
	}

	queue := make([]string, 0)
	for node := range graph {
		if indegree[node] == 0 {
			queue = append(queue, node)
		}
	}
	sort.Slice(queue, func(i, j int) bool { return less(queue[i], queue[j]) })

	order = make([]string, 0, N)

	front := 0
	for len(queue) > 0 {
		// Pop the alphabetically-first ready node
		curr := queue[front]
		queue = queue[1:]
		order = append(order, curr)

		// new eligible nodes
		var newEntries []string
		for _, dep := range graph[curr] {
			indegree[dep]--
			if indegree[dep] == 0 {
				newEntries = append(newEntries, dep)
			}
		}

		sort.Strings(newEntries)
		sort.Slice(newEntries, func(i, j int) bool { return less(newEntries[i], newEntries[j]) })
		queue = mergeSorted(queue, newEntries, less) // keep 'queue' sorted as new nodes join
	}

	if len(order) != N {
		// return remaining indegree nodes as cycles
		return nil, findCyclePath(graph, indegree), false
	}

	return order, nil, true
}

func mergeSorted(a, b []string, less func(a, b string) bool) []string {
	if len(b) == 0 {
		return a
	}
	out := make([]string, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if !less(b[j], a[i]) { // a[i] <= b[j]
			out = append(out, a[i])
			i++
		} else {
			out = append(out, b[j])
			j++
		}
	}
	return append(append(out, a[i:]...), b[j:]...)
}

// findCyclePath walks from any node that still has unresolved in-degree
// (proof it's part of, or downstream of, a cycle) following one dependency
// edge at a time until a node repeats, which marks the actual cycle,
// trimmed out of the full walk for a concise, readable report.
func findCyclePath(graph map[string][]string, remainingInDegree map[string]int) []string {
	// Build the reverse (dependency-direction) map once, for walking;
	// since the graph i sin dependant-direction
	dependsOn := make(map[string][]string)
	for node, dependants := range graph {
		for _, d := range dependants {
			dependsOn[d] = append(dependsOn[d], node)
		}
	}

	var start string
	for n, deg := range remainingInDegree {
		if deg > 0 {
			start = n
			break
		}
	}

	if start == "" {
		return nil // defensive: shouldn't happen if the caller already confirmed a cycle exists
	}

	visited := map[string]bool{}
	path := []string{start}
	current := start
	for {
		next := dependsOn[current]
		if len(next) == 0 {
			return path // dead end without a repeat. shouldn't occur in a genuine cycle
		}
		sort.Strings(next) // deterministic even when a node has multiple unresolved dependencies
		current = next[0]
		if visited[current] {
			path = append(path, current)
			// Trim everything before the repeat's first occurrence,
			// so the reported path is exactly the cycle.
			for i, n := range path {
				if n == current {
					return path[i:]
				}
			}
		}
		visited[current] = true
		path = append(path, current)
	}
}
