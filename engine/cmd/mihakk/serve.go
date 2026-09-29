package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"mihakk/internal/api"
	"mihakk/internal/audit"
	"mihakk/internal/safety"
	"mihakk/internal/store"
)

// socketMode is what the control socket is set to once it exists: the engine's
// user and the group it shares with the orchestrator, and nobody else. The
// directory it lives in is checked as well, because a socket's own mode is set
// only after it has been created.
const socketMode fs.FileMode = 0o660

// serveCmd runs the control API.
//
// There are two ways to listen, and the difference is the point of phase 8a.
//
// TCP (-addr) defaults to loopback. It is what the tests' stub setups and a
// developer's local run use.
//
// A Unix socket (-socket) puts the control API on no network at all. The engine
// is the component that joins an operator's network to reach their application,
// and a TCP listener on 0.0.0.0 would have come along with it: every neighbour
// on that network would have had the control API one connection away, guarded by
// the token alone. On a socket there is nothing on any network to connect to,
// which is a property of the process rather than of a firewall rule. The token
// stays mandatory all the same.
func serveCmd(args []string) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := flags.String("addr", "127.0.0.1:8900", "TCP address to listen on (not with -socket)")
	socketPath := flags.String("socket", "", "serve the control API on this Unix socket instead of TCP")
	healthAddr := flags.String("health-addr", "",
		"loopback-only address for an unauthenticated liveness endpoint (only with -socket)")
	dataDir := flags.String("data", "./data", "directory for sessions, cases and the audit log")
	bufferCap := flags.Int("event-buffer", api.DefaultBufferCapacity,
		"how many events each run retains for consumers that fall behind")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	addrGiven := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "addr" {
			addrGiven = true
		}
	})
	if err := validateListenFlags(*socketPath, addrGiven, *healthAddr); err != nil {
		fmt.Fprintf(os.Stderr, "mihakk: %v\n", err)
		return 2
	}

	// The token comes from the environment, never a flag: a flag would put it
	// in the process list for anything on the host to read.
	token := os.Getenv("MIHAKK_CONTROL_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr,
			"mihakk: MIHAKK_CONTROL_TOKEN must be set. The control API can start a run,\n"+
				"so leaving it unauthenticated would let anything that reaches the port make\n"+
				"the engine send traffic on someone else's behalf.")
		return 2
	}

	st, err := store.Open(*dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mihakk: %v\n", err)
		return 1
	}
	auditLog, err := audit.Open(filepath.Join(*dataDir, "audit.jsonl"), safety.NewRedactor())
	if err != nil {
		fmt.Fprintf(os.Stderr, "mihakk: %v\n", err)
		return 1
	}

	server, err := api.New(api.Config{
		Token: token, EngineVersion: Version,
		Store: st, Audit: auditLog, BufferCapacity: *bufferCap,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "mihakk: %v\n", err)
		return 1
	}

	var listener net.Listener
	if *socketPath != "" {
		listener, err = listenControlSocket(*socketPath)
	} else {
		listener, err = net.Listen("tcp", *addr)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "mihakk: %v\n", err)
		return 1
	}

	httpServer := &http.Server{
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	servers := []*http.Server{httpServer}
	serveErr := make(chan error, 2)
	go func() { serveErr <- httpServer.Serve(listener) }()

	if *healthAddr != "" {
		healthListener, err := net.Listen("tcp", *healthAddr)
		if err != nil {
			_ = listener.Close()
			fmt.Fprintf(os.Stderr, "mihakk: health endpoint on %s: %v\n", *healthAddr, err)
			return 1
		}
		healthServer := &http.Server{
			Handler:           healthOnly(server.Handler()),
			ReadHeaderTimeout: 5 * time.Second,
		}
		servers = append(servers, healthServer)
		go func() { serveErr <- healthServer.Serve(healthListener) }()
		fmt.Printf("mihakk liveness on %s (loopback, /healthz only)\n", healthListener.Addr())
	}

	fmt.Printf("mihakk control API on %s\n", describeListener(listener))
	fmt.Printf("  engine version : %s\n", Version)
	fmt.Printf("  data           : %s\n", *dataDir)
	fmt.Printf("  auth           : shared token (every endpoint but /healthz)\n")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	shutdown := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, s := range servers {
			_ = s.Shutdown(shutdownCtx)
		}
	}

	select {
	case <-ctx.Done():
		fmt.Println("\nshutting down; stopping every run")
		// Stop the runs before the HTTP server: a run still sending traffic
		// after the API has gone is exactly what the kill switch is for.
		server.StopAll()
		shutdown()
		return 0
	case err := <-serveErr:
		server.StopAll()
		shutdown()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "mihakk: %v\n", err)
			return 1
		}
		return 0
	}
}

// validateListenFlags refuses the combinations that would be ambiguous or that
// would quietly put something on a network.
func validateListenFlags(socketPath string, addrGiven bool, healthAddr string) error {
	if socketPath != "" && addrGiven {
		return errors.New("-socket and -addr are alternatives; give one of them")
	}
	if healthAddr != "" && socketPath == "" {
		return errors.New("-health-addr is only for -socket: over TCP, /healthz is already on -addr")
	}
	if healthAddr != "" {
		if err := requireLoopback(healthAddr); err != nil {
			return err
		}
	}
	if socketPath != "" && !filepath.IsAbs(socketPath) {
		return fmt.Errorf("-socket must be an absolute path, got %q", socketPath)
	}
	return nil
}

// requireLoopback accepts a literal loopback IP and a port, and nothing else.
//
// A host name is refused rather than resolved: "localhost" is whatever the
// resolver says it is, and the point of this flag is that the liveness endpoint
// cannot end up on the network the engine shares with an operator's application.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("-health-addr %q is not host:port: %v", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("-health-addr must be a literal loopback address, not the name %q", host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("-health-addr must be loopback; %s would be reachable from a network", host)
	}
	return nil
}

// listenControlSocket creates the control socket, refusing the ways it could end
// up reachable by someone it was not meant for.
//
// The directory is checked before the socket exists because the socket's own
// mode can only be set after it has been created. Between those two moments the
// directory is the only thing standing between the socket and every other user,
// so a directory other users can enter is refused outright.
//
// A leftover socket from an earlier run is replaced; anything else at that path
// is refused rather than removed, because it is not this process's to delete.
func listenControlSocket(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("control socket directory %s: %v", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("control socket directory %s is not a directory", dir)
	}
	if perm := info.Mode().Perm(); perm&0o007 != 0 {
		return nil, fmt.Errorf("control socket directory %s is open to other users (mode %04o); "+
			"it must grant nothing to 'other'", dir, perm)
	}

	existing, err := os.Lstat(path)
	switch {
	case err == nil && existing.Mode()&fs.ModeSocket != 0:
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("removing the stale control socket %s: %v", path, err)
		}
	case err == nil:
		return nil, fmt.Errorf("%s exists and is not a socket (%s); refusing to replace it",
			path, existing.Mode().Type())
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("control socket %s: %v", path, err)
	}

	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %v", path, err)
	}
	if err := os.Chmod(path, socketMode); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("restricting %s to %04o: %v", path, socketMode, err)
	}
	return listener, nil
}

// healthOnly exposes the liveness route of the control API and nothing else.
// The endpoint is unauthenticated, so it must not become a second way in.
func healthOnly(full http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", full)
	return mux
}

func describeListener(l net.Listener) string {
	if l.Addr().Network() == "unix" {
		return "unix socket " + l.Addr().String()
	}
	return l.Addr().String()
}
