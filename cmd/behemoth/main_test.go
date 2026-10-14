package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTree creates files under root. Keys are slash-separated paths.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFindApp(t *testing.T) {
	const setup = "package auth\n"

	for name, tc := range map[string]struct {
		files   map[string]string
		want    string // relative to the root; "" expects an error
		wantErr string
	}{
		"in a package below": {
			files: map[string]string{"main.go": "package main\n", "internal/auth/behemoth.go": setup},
			want:  "internal/auth",
		},
		"in the directory itself": {
			files: map[string]string{"behemoth.go": setup},
			want:  ".",
		},
		"none": {
			files:   map[string]string{"auth/setup.go": setup},
			wantErr: "no behemoth.go",
		},
		"two": {
			files:   map[string]string{"api/auth/behemoth.go": setup, "admin/auth/behemoth.go": setup},
			wantErr: "2 packages have a behemoth.go",
		},
		"ignored directories and another module": {
			files: map[string]string{
				"auth/behemoth.go":           setup,
				".cache/x/behemoth.go":       setup,
				"_old/behemoth.go":           setup,
				"testdata/app/behemoth.go":   setup,
				"vendor/dep/behemoth.go":     setup,
				"tools/go.mod":               "module tools\n",
				"tools/internal/behemoth.go": setup,
			},
			want: "auth",
		},
	} {
		root := t.TempDir()
		writeTree(t, root, tc.files)

		got, err := findApp(root)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: err = %v, want one containing %q", name, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if want := filepath.Join(root, filepath.FromSlash(tc.want)); got != want {
			t.Errorf("%s: found %s, want %s", name, got, want)
		}
	}
}

func TestCheckEntryPoints(t *testing.T) {
	const both = `package auth

func Prepare()          {}
func MigrationBackend() {}
`
	for name, tc := range map[string]struct {
		pkgName string
		files   map[string]string
		wantErr string
	}{
		"both functions, in two files": {
			pkgName: "auth",
			files: map[string]string{
				"behemoth.go": "package auth\n\nfunc Prepare() {}\n",
				"db.go":       "package auth\n\nfunc MigrationBackend() {}\n",
			},
		},
		"one missing": {
			pkgName: "auth",
			files:   map[string]string{"behemoth.go": "package auth\n\nfunc Prepare() {}\n"},
			wantErr: "does not export MigrationBackend",
		},
		"a method does not count": {
			pkgName: "auth",
			files: map[string]string{"behemoth.go": `package auth

type app struct{}

func (app) Prepare()    {}
func MigrationBackend() {}
`},
			wantErr: "does not export Prepare",
		},
		"package main": {
			pkgName: "main",
			files:   map[string]string{"behemoth.go": strings.Replace(both, "package auth", "package main", 1)},
			wantErr: "is package main",
		},
	} {
		dir := t.TempDir()
		writeTree(t, dir, tc.files)
		pkg := goPackage{Dir: dir, ImportPath: "example.com/shop/auth", Name: tc.pkgName}
		for file := range tc.files {
			pkg.GoFiles = append(pkg.GoFiles, file)
		}

		err := checkEntryPoints(pkg)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: err = %v, want one containing %q", name, err, tc.wantErr)
		}
	}
}

func TestMainSource(t *testing.T) {
	src, err := mainSource("example.com/shop/internal/auth")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"github.com/MastewalB/behemoth/cli"`,
		`app "example.com/shop/internal/auth"`,
		"cli.Main(app.Prepare, app.MigrationBackend)",
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("the generated main lacks %s:\n%s", want, src)
		}
	}
}

func TestVirtualDirAvoidsAnExistingOne(t *testing.T) {
	dir := t.TempDir()
	first := virtualDir(dir)
	if err := os.Mkdir(first, 0o755); err != nil {
		t.Fatal(err)
	}
	if second := virtualDir(dir); second == first {
		t.Errorf("virtualDir returned %s, which exists", second)
	}
}

func TestLauncherFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-h"}, nil, &stdout, &stderr); code != 0 || !strings.Contains(stderr.String(), "Usage: behemoth [-app dir]") {
		t.Errorf("-h: exit code = %d, stderr = %q", code, stderr.String())
	}
	stderr.Reset()
	if code := run([]string{"-nope", "generate"}, nil, &stdout, &stderr); code != exitUsage {
		t.Errorf("unknown launcher flag: exit code = %d, want %d", code, exitUsage)
	}
}

// The launcher against a module on disk: it finds the setup in an internal
// package, builds the command line with the overlay and runs it. The
// application's backend reports an empty database, so no database is needed.
func TestLauncherRunsAnApplication(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a program with the go command")
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	gomod, err := os.ReadFile(filepath.Join(repo, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	gosum, err := os.ReadFile(filepath.Join(repo, "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	goLine := "go 1.26"
	for _, line := range strings.Split(string(gomod), "\n") {
		if strings.HasPrefix(line, "go ") {
			goLine = line
		}
	}

	module := t.TempDir()
	writeTree(t, module, map[string]string{
		"go.mod": "module example.com/shop\n\n" + goLine + "\n\n" +
			"require github.com/MastewalB/behemoth v0.0.0\n\n" +
			"replace github.com/MastewalB/behemoth v0.0.0 => " + repo + "\n",
		"go.sum": string(gosum),
		"internal/auth/behemoth.go": `package auth

import (
	"context"

	"github.com/MastewalB/behemoth/migration/core"
	bmth "github.com/MastewalB/behemoth/types/init"
)

func Prepare() (*bmth.PreparedApp, error) {
	return bmth.Prepare(nil, bmth.PrepareConfig{Migration: core.MigrationConfig{FolderPath: "migrations"}})
}

func MigrationBackend(context.Context, *bmth.PreparedApp) (core.Backend, error) {
	return core.Backend{Introspector: empty{}}, nil
}

// empty is a database without tables.
type empty struct{}

func (empty) TableExists(context.Context, string) (bool, error) { return false, nil }
func (empty) Introspect(context.Context, string) (core.IntrospectedTable, error) {
	return core.IntrospectedTable{}, nil
}
`,
	})

	// The module's go.mod lists only behemoth: let the go command add what
	// behemoth requires, from the module cache alone.
	t.Setenv("GOFLAGS", "-mod=mod")
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOWORK", "off")
	t.Setenv(appEnv, "")
	t.Chdir(module)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"generate", "-confirm"}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("generate -confirm: exit code = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "create table users") {
		t.Errorf("stdout lacks the plan:\n%s", stdout.String())
	}
	// Written by the application's process, in the directory the launcher ran in.
	if _, err := os.Stat(filepath.Join(module, "migrations", "0001_create_accounts_and_5_more.json")); err != nil {
		t.Errorf("the migration was not written: %v", err)
	}

	// Nothing of the build is left in the application's tree.
	entries, err := os.ReadDir(filepath.Join(module, "internal", "auth"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != entryFile {
		t.Errorf("the setup package now holds %v, want %s alone", entries, entryFile)
	}

	// The exit code is the command line's own, not the go command's.
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"deploy"}, nil, &stdout, &stderr); code != exitUsage || !strings.Contains(stderr.String(), `unknown command "deploy"`) {
		t.Errorf("unknown command: exit code = %d, stderr = %q; want %d from the command line", code, stderr.String(), exitUsage)
	}
}
