package main

import (
	"context"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The control socket is the reason the engine can join an operator's network
// without bringing the control API along. These pin down the ways it could still
// end up reachable by someone it was not meant for.

func TestHealthAddrMustBeALiteralLoopbackAddress(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8901", "[::1]:8901", "127.0.0.2:1"} {
		if err := requireLoopback(addr); err != nil {
			t.Errorf("%s was refused: %v", addr, err)
		}
	}
	// 0.0.0.0 is every interface, including the one on the operator's network;
	// a name is whatever the resolver says; 192.0.2.1 is TEST-NET-1.
	for _, addr := range []string{"0.0.0.0:8901", "[::]:8901", ":8901",
		"localhost:8901", "192.0.2.1:8901", "not-an-address"} {
		if err := requireLoopback(addr); err == nil {
			t.Errorf("%s was accepted as a loopback liveness address", addr)
		}
	}
}

func TestListenFlagCombinations(t *testing.T) {
	cases := []struct {
		name      string
		socket    string
		addrGiven bool
		health    string
		ok        bool
	}{
		{"tcp alone", "", true, "", true},
		{"socket alone", "/run/mihakk/control.sock", false, "", true},
		{"socket with loopback health", "/run/mihakk/control.sock", false, "127.0.0.1:8901", true},
		{"socket and addr together", "/run/mihakk/control.sock", true, "", false},
		{"health without socket", "", false, "127.0.0.1:8901", false},
		{"socket with public health", "/run/mihakk/control.sock", false, "0.0.0.0:8901", false},
		{"relative socket", "control.sock", false, "", false},
	}
	for _, tc := range cases {
		err := validateListenFlags(tc.socket, tc.addrGiven, tc.health)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestServeRefusesAmbiguousFlagsBeforeAnythingElse(t *testing.T) {
	// No token set: the flag check has to come first, or a mistaken invocation
	// would be reported as a missing token.
	t.Setenv("MIHAKK_CONTROL_TOKEN", "")
	if got := serveCmd([]string{"-socket", "/tmp/x.sock", "-addr", "127.0.0.1:0"}); got != 2 {
		t.Fatalf("serve with -socket and -addr returned %d, want 2", got)
	}
}

func socketDir(t *testing.T, mode fs.FileMode) string {
	t.Helper()
	// Unix socket paths are limited to ~104 bytes; t.TempDir can be longer.
	dir, err := os.MkdirTemp("/tmp", "mk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestTheSocketIsRestrictedToOwnerAndGroup(t *testing.T) {
	dir := socketDir(t, 0o770)
	path := filepath.Join(dir, "control.sock")

	l, err := listenControlSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&fs.ModeSocket == 0 {
		t.Fatalf("%s is %s, not a socket", path, info.Mode().Type())
	}
	if got := info.Mode().Perm(); got != 0o660 {
		t.Fatalf("socket mode is %04o, want 0660", got)
	}
}

func TestADirectoryOpenToOtherUsersIsRefused(t *testing.T) {
	for _, mode := range []fs.FileMode{0o777, 0o771, 0o774, 0o775} {
		dir := socketDir(t, mode)
		l, err := listenControlSocket(filepath.Join(dir, "control.sock"))
		if err == nil {
			l.Close()
			t.Errorf("a socket directory with mode %04o was accepted", mode)
			continue
		}
		if !strings.Contains(err.Error(), "other users") {
			t.Errorf("mode %04o refused for the wrong reason: %v", mode, err)
		}
	}
}

func TestAStaleSocketIsReplacedButAnythingElseIsRefused(t *testing.T) {
	dir := socketDir(t, 0o770)
	path := filepath.Join(dir, "control.sock")

	first, err := listenControlSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	// Leave the file behind the way a killed process does.
	first.(*net.UnixListener).SetUnlinkOnClose(false)
	first.Close()

	second, err := listenControlSocket(path)
	if err != nil {
		t.Fatalf("a stale socket was not replaced: %v", err)
	}
	second.Close()

	regular := filepath.Join(dir, "precious")
	if err := os.WriteFile(regular, []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	if l, err := listenControlSocket(regular); err == nil {
		l.Close()
		t.Fatal("a regular file at the socket path was replaced")
	}
	if data, err := os.ReadFile(regular); err != nil || string(data) != "not ours" {
		t.Fatalf("the refused file was changed: %q, %v", data, err)
	}
}

func TestTheSocketServesTheControlAPI(t *testing.T) {
	dir := socketDir(t, 0o770)
	path := filepath.Join(dir, "control.sock")
	l, err := listenControlSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok " + r.URL.Path))
	})}
	go server.Serve(l)
	defer server.Close()

	// A test-only client over the socket. It lives in a _test.go file, which the
	// outbound-request check in internal/runner deliberately does not scan.
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
	}, Timeout: 5 * time.Second}
	resp, err := client.Get("http://engine/v1/runs/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d over the socket", resp.StatusCode)
	}
}

func TestTheLivenessEndpointExposesNothingElse(t *testing.T) {
	full := http.NewServeMux()
	full.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	full.HandleFunc("POST /v1/runs", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("started")) })
	full.HandleFunc("GET /v1/runs/{id}", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("status")) })

	h := healthOnly(full)
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/healthz", 200},
		{"POST", "/v1/runs", 404},
		{"GET", "/v1/runs/x", 404},
		{"POST", "/healthz", 405},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.want {
			t.Errorf("%s %s: %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}
}
