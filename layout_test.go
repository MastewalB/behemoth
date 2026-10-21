package behemoth_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// layoutRows are the rows of docs/internal/plans/package_layout.md, in
// order. A package imports only packages of earlier rows, except where
// sameRow allows it or noImport forbids it. A pattern names a directory
// relative to the repository's root, and one that ends in "/*" also names
// every directory below it. The most specific pattern of a directory wins.
var layoutRows = [][]string{
	{"clause", "utils", "identity", "storage"},
	{"."}, // the root package, behemoth
	{"errs"},
	{"telemetry"},
	{"schema", "outbound", "telemetry/*"},
	{"models", "crypto"},
	{"store", "migration", "keysource", "storage/adapters", "storage/adapters/*"},
	{"core"},
	{"core/hooks"},
	{"auth", "dispatch", "ratelimit", "messaging"},
	{"httpapi"},
	{"plugins/*"},
	{"engine", "cli", "cmd/*"},
	{"examples/*", "tests", "tests/*"},
}

// sameRow lists the imports allowed within one row, as importer pattern and
// imported directory.
var sameRow = map[string][]string{
	"storage/adapters/*":  {"storage/adapters", "migration"},
	"plugins/username":    {"plugins/emailpassword"},
	"plugins/phonenumber": {"plugins/emailpassword"},
	"plugins/twofactor":   {"plugins/twofactor/totp", "plugins/phonenumber"},
	"cli":                 {"engine"},
	"cmd/*":               {"cli", "engine"},
}

// noImport lists the rows a row may not import although they come earlier:
// httpapi and a plugin reach the implementations only through the contracts
// in core, so that an application can replace an implementation.
var noImport = map[int][]int{10: {9}, 11: {9}}

const modulePath = "github.com/MastewalB/behemoth"

// TestPackageLayout checks that every package of the repository, in every
// module, imports Behemoth's packages only in the order of layoutRows. Test
// files are left out: a test may import whatever it exercises.
func TestPackageLayout(t *testing.T) {
	imports := map[string]map[string]bool{} // directory -> imported directories
	for _, path := range goFiles(t) {
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.ToSlash(filepath.Dir(path))
		if imports[dir] == nil {
			imports[dir] = map[string]bool{}
		}
		for _, spec := range f.Imports {
			p, _ := strconv.Unquote(spec.Path.Value)
			if p != modulePath && !strings.HasPrefix(p, modulePath+"/") {
				continue
			}
			imported := strings.TrimPrefix(strings.TrimPrefix(p, modulePath), "/")
			if imported == "" {
				imported = "."
			}
			if imported != dir {
				imports[dir][imported] = true
			}
		}
	}

	for dir, imported := range imports {
		row, pattern := rowOf(dir)
		if row < 0 {
			t.Errorf("%s has no row in layoutRows: add it where docs/internal/plans/package_layout.md places it", dir)
			continue
		}
		if row == len(layoutRows)-1 {
			continue // the examples and the tests may import anything
		}
		for imp := range imported {
			impRow, _ := rowOf(imp)
			switch {
			case impRow < 0:
				t.Errorf("%s imports %s, which has no row in layoutRows", dir, imp)
			case impRow == row && (contains(sameRow[dir], imp) || contains(sameRow[pattern], imp)):
			case impRow >= row:
				t.Errorf("%s (row %d) imports %s (row %d): a package imports only earlier rows", dir, row+1, imp, impRow+1)
			case containsInt(noImport[row], impRow):
				t.Errorf("%s (row %d) imports %s (row %d): this row reaches that one only through core", dir, row+1, imp, impRow+1)
			}
		}
	}
}

// rowOf returns the row of dir and the pattern that placed it there, or -1.
func rowOf(dir string) (int, string) {
	best, bestPattern, bestLen := -1, "", -1
	for i, patterns := range layoutRows {
		for _, p := range patterns {
			matched := p == dir
			if prefix, ok := strings.CutSuffix(p, "/*"); ok {
				matched = strings.HasPrefix(dir, prefix+"/")
			}
			if matched && len(p) > bestLen {
				best, bestPattern, bestLen = i, p, len(p)
			}
		}
	}
	return best, bestPattern
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func containsInt(list []int, n int) bool {
	for _, v := range list {
		if v == n {
			return true
		}
	}
	return false
}

// goFiles returns the path of every Go file of the repository that isn't a
// test, in every module. Directories that hold no packages of Behemoth are
// left out.
func goFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != "." && (strings.HasPrefix(name, ".") || name == "docs" || name == "testdata" || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// signedInBuilders are the packages that may build a signed-in caller. Such a
// caller holds a user's rights, so a package that builds one without an
// authenticator bypasses authentication. See ADR-0005.
var signedInBuilders = map[string]bool{"auth": true}

// TestOnlyAuthBuildsSignedInCallers checks that identity.SignedIn is called
// from the packages of signedInBuilders only. Test files are left out.
func TestOnlyAuthBuildsSignedInCallers(t *testing.T) {
	for _, path := range goFiles(t) {
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		local := "" // the name the file imports identity by
		for _, spec := range f.Imports {
			if p, _ := strconv.Unquote(spec.Path.Value); p == modulePath+"/identity" {
				local = "identity"
				if spec.Name != nil {
					local = spec.Name.Name
				}
			}
		}
		if local == "" {
			continue
		}
		dir := filepath.ToSlash(filepath.Dir(path))
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "SignedIn" {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == local && !signedInBuilders[dir] {
				t.Errorf("%s calls identity.SignedIn: only an authenticator, in package auth, builds a signed-in caller", path)
			}
			return true
		})
	}
}

// serverSideHTTP are the names of net/http that serve a request: what an
// HTTP handler, a router, or a cookie on a response is made of. The packages
// below httpapi know no transport, so they name none of them. A prefix ends
// in "*".
var serverSideHTTP = []string{
	"Request", "ResponseWriter", "Handler", "HandlerFunc", "ServeMux", "NewServeMux",
	"Server", "Serve", "ServeTLS", "ListenAndServe", "ListenAndServeTLS",
	"Cookie", "SetCookie", "SameSite*", "Redirect", "Error", "NotFound", "NotFoundHandler",
	"StripPrefix", "FileServer", "ServeFile", "ServeContent", "MaxBytesReader", "TimeoutHandler",
	"Flusher", "Hijacker", "Pusher", "ResponseController", "NewResponseController", "ErrAbortHandler",
}

// clientRequests are the packages below httpapi that send requests to other
// services, and so may name http.Request for the requests they build. They
// name no other name of serverSideHTTP.
var clientRequests = map[string]bool{"outbound": true}

// TestNoServerSideHTTPBelowHTTPAPI checks the import rule of
// docs/internal/guidelines/transport_neutral_flows.md: no package in a row
// before httpapi's uses the server side of net/http (serverSideHTTP). The
// client side, such as http.Client, is allowed. Test files are left out.
func TestNoServerSideHTTPBelowHTTPAPI(t *testing.T) {
	httpRow, _ := rowOf("httpapi")
	for _, path := range goFiles(t) {
		dir := filepath.ToSlash(filepath.Dir(path))
		if row, _ := rowOf(dir); row < 0 || row >= httpRow {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		local := "" // the name the file imports net/http by
		for _, spec := range f.Imports {
			if p, _ := strconv.Unquote(spec.Path.Value); p == "net/http" {
				local = "http"
				if spec.Name != nil {
					local = spec.Name.Name
				}
			}
		}
		if local == "" {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != local || !isServerSideHTTP(sel.Sel.Name) {
				return true
			}
			if sel.Sel.Name == "Request" && clientRequests[dir] {
				return true
			}
			t.Errorf("%s uses http.%s: only httpapi and the packages after it serve HTTP", path, sel.Sel.Name)
			return true
		})
	}
}

func isServerSideHTTP(name string) bool {
	for _, s := range serverSideHTTP {
		if prefix, ok := strings.CutSuffix(s, "*"); ok && strings.HasPrefix(name, prefix) || name == s {
			return true
		}
	}
	return false
}
