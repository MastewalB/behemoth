package main

import (
	"log"
	"sort"
	"strings"

	"github.com/go-behemoth/behemoth/core"
)

// trace logs one hook handler call: who ran, on which point and phase, where
// the operation came from, and which keys its Values hold at that moment.
// The dispatcher fills in Point and Phase, so no handler passes them along.
//
// Reading the output of one sign-up top to bottom shows how Values travel:
// the points of one operation share a map, and an operation nested in
// another (the user write inside the sign-up) starts with a copy of it.
func trace(owner string, hctx *core.HookContext, msg string) {
	keys := make([]string, 0, len(hctx.Values))
	for k := range hctx.Values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	log.Printf("[%-8s] %-26s %-6s via %-4s values=[%s]  %s",
		owner, hctx.Point, hctx.Phase, source(hctx), strings.Join(keys, " "), msg)
}

// source says how the operation was started: the transport on its caller,
// which the signup command, calling the flows without an HTTP request, does
// not set.
func source(hctx *core.HookContext) string {
	if transport := hctx.Caller().Peer().Transport; transport != "" {
		return transport
	}
	return "cli"
}
