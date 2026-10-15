// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"

	"github.com/postmanlabs/postman-insights-agent/ebpf/discovery"
	"github.com/postmanlabs/postman-insights-agent/ebpf/javatls"
	"github.com/postmanlabs/postman-insights-agent/ebpf/jvm"
	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
)

// These tests run the DaemonSet path end to end with real JVMs and the real
// Java agent. Each JVM runs as uid 1000 in its own mount namespace with a
// private /tmp, as in a container. They require root, util-linux (unshare,
// setpriv), Go (to build the attach helper), and:
//
//	POSTMAN_TEST_JAVA_HOME  a JDK, 8 or newer
//	POSTMAN_TEST_AGENT_JAR  java-agent/build/agent/postman-java-agent.jar
//
// They are skipped when those are not set.

// jvmServer is a small HTTPS server on the JDK's own SSLEngine.
const jvmServer = `
import com.sun.net.httpserver.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import javax.net.ssl.*;

public class Server {
    public static void main(String[] args) throws Exception {
        if (args[0].equals("client")) {
            client(args[1]);
            return;
        }
        char[] pw = "changeit".toCharArray();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(args[0])) {
            ks.load(in, pw);
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, pw);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        HttpsServer s = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        s.setHttpsConfigurator(new HttpsConfigurator(ctx));
        s.createContext("/hello", ex -> {
            byte[] b = "{\"hello\":\"jvm\"}".getBytes();
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        s.start();
        System.out.println("listening " + s.getAddress().getPort());
    }

    // A blocking client (HttpsURLConnection, on SSLSocket): a request every
    // 200 ms, each on a new connection, trusting any certificate.
    static void client(String url) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[] {new X509TrustManager() {
            public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
        }}, null);
        System.out.println("client started");
        for (;;) {
            HttpsURLConnection c = (HttpsURLConnection) new java.net.URL(url).openConnection();
            c.setSSLSocketFactory(ctx.getSocketFactory());
            c.setHostnameVerifier((h, sess) -> true);
            c.setRequestProperty("Connection", "close");
            try (InputStream in = c.getInputStream()) {
                while (in.read() >= 0) {}
            } catch (IOException e) {
                System.out.println("client error " + e);
            }
            Thread.sleep(200);
        }
    }
}
`

// syncBuffer collects a process's output for assertions while it runs.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// jvmFixture holds what the JVM tests share: a directory with the server, a
// keystore and the agent jar, readable by uid 1000.
type jvmFixture struct {
	javaHome, dir, agentJar, keystore string
}

func newJVMFixture(t *testing.T) *jvmFixture {
	t.Helper()
	javaHome, agentJar := os.Getenv("POSTMAN_TEST_JAVA_HOME"), os.Getenv("POSTMAN_TEST_AGENT_JAR")
	if javaHome == "" || agentJar == "" {
		t.Skip("set POSTMAN_TEST_JAVA_HOME and POSTMAN_TEST_AGENT_JAR to run")
	}
	for _, tool := range []string{"unshare", "setpriv"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found", tool)
		}
	}
	// Outside /tmp, which each JVM's mount namespace replaces.
	dir, err := os.MkdirTemp("/var/tmp", "jvm-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	jar, err := os.ReadFile(agentJar)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(jar)
	f := &jvmFixture{javaHome: javaHome, dir: dir, agentJar: filepath.Join(dir, "postman-java-agent.jar"), keystore: filepath.Join(dir, "server.p12")}
	for name, content := range map[string][]byte{
		"Server.java":                   []byte(jvmServer),
		"postman-java-agent.jar":        jar,
		"postman-java-agent.jar.sha256": []byte(hex.EncodeToString(sum[:]) + "  postman-java-agent.jar\n"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command(filepath.Join(javaHome, "bin", "keytool"), "-genkeypair", "-alias", "s",
		"-keyalg", "RSA", "-keysize", "2048", "-dname", "CN=localhost", "-validity", "1",
		"-storetype", "PKCS12", "-keystore", f.keystore, "-storepass", "changeit").CombinedOutput(); err != nil {
		t.Fatalf("keytool: %v\n%s", err, out)
	}
	if err := os.Chmod(f.keystore, 0o644); err != nil {
		t.Fatal(err)
	}
	// Compiled, rather than run with the source launcher, so the tests run
	// on JDK 8 too.
	if out, err := exec.Command(filepath.Join(javaHome, "bin", "javac"), "-d", dir,
		filepath.Join(dir, "Server.java")).CombinedOutput(); err != nil {
		t.Fatalf("javac: %v\n%s", err, out)
	}
	if err := os.Chmod(filepath.Join(dir, "Server.class"), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

// attacher builds the attach helper and returns an Attacher using it, as the
// DaemonSet's NodeCollector does with the files in its image.
func (f *jvmFixture) attacher(t *testing.T) *jvm.Attacher {
	t.Helper()
	helper := filepath.Join(f.dir, "postman-jvm-attach")
	if _, err := os.Stat(helper); err != nil {
		build := exec.Command("go", "build", "-o", helper, "github.com/postmanlabs/postman-insights-agent/cmd/postman-jvm-attach")
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build the attach helper: %v\n%s", err, out)
		}
	}
	a, err := jvm.NewAttacher(jvm.AttacherConfig{
		HelperPath:   helper,
		JarPath:      f.agentJar,
		ChecksumPath: f.agentJar + ".sha256",
		AgentArgs:    func() string { return javatls.ArgCaptureCap + "=16384" },
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// testJVM is a running JVM server.
type testJVM struct {
	addr           string
	stdout, stderr *syncBuffer
	cmd            *exec.Cmd
}

// start runs the server as uid in a new mount namespace with a private /tmp,
// with the given JVM options and environment.
func (f *jvmFixture) start(t *testing.T, uid int, env []string, jvmArgs ...string) *testJVM {
	t.Helper()
	return f.startMain(t, uid, env, []string{f.keystore}, jvmArgs...)
}

// startClient starts a JVM running the blocking HTTPS client, requesting url.
func (f *jvmFixture) startClient(t *testing.T, uid int, url string, jvmArgs ...string) *testJVM {
	t.Helper()
	return f.startMain(t, uid, nil, []string{"client", url}, jvmArgs...)
}

// startMain starts the test program with mainArgs and waits until it says
// it is listening (the server, whose address it records) or started (the
// client).
func (f *jvmFixture) startMain(t *testing.T, uid int, env []string, mainArgs []string, jvmArgs ...string) *testJVM {
	t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	id := strconv.Itoa(uid)
	args := append([]string{"--mount", "--propagation", "private", "sh", "-ec",
		`mount -t tmpfs tmpfs /tmp
exec setpriv --reuid "$0" --regid "$0" --clear-groups "$@"`, id,
		filepath.Join(f.javaHome, "bin", "java")}, jvmArgs...)
	args = append(append(args, "-cp", f.dir, "Server"), mainArgs...)
	cmd := exec.CommandContext(ctx, "unshare", args...)
	cmd.Env = append([]string{"PATH=/usr/bin:/bin"}, env...)
	j := &testJVM{stdout: &syncBuffer{}, stderr: &syncBuffer{}, cmd: cmd}
	cmd.Stderr = j.stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("JVM stdout:\n%s\nJVM stderr:\n%s", j.stdout, j.stderr)
		}
	})
	port := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			line := sc.Text()
			_, _ = j.stdout.Write([]byte(line + "\n"))
			if p, ok := strings.CutPrefix(line, "listening "); ok {
				port <- p
			} else if line == "client started" {
				port <- ""
			}
		}
	}()
	select {
	case p := <-port:
		if p != "" {
			j.addr = "127.0.0.1:" + p
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the JVM did not start")
	}
	return j
}

// waitLog waits until the JVM's stderr contains what.
func (j *testJVM) waitLog(t *testing.T, what string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !strings.Contains(j.stderr.String(), what) {
		if time.Now().After(deadline) {
			t.Fatalf("the JVM did not log %q", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// subscribe subscribes this netns, where the test JVMs run, as a pod.
// reportCount, when not nil, receives the pod's telemetry counters.
func subscribe(t *testing.T, ctx context.Context, nc *NodeCollector, reportCount func(string, uint64)) (<-chan akinet.ParsedNetworkTraffic, context.CancelFunc) {
	t.Helper()
	subCtx, cancel := context.WithCancel(ctx)
	out := make(chan akinet.ParsedNetworkTraffic, 64)
	disco := discovery.WatchWith(subCtx, discovery.WatchOpts{
		Interval:         200 * time.Millisecond,
		ProcRoot:         "/proc",
		NetnsInodeFilter: ownNetns(t),
		JVMs:             true,
	})
	unsubscribe, _ := nc.Subscribe(subCtx, disco, httpSelector(t), out, "", ownNetns(t), reportCount)
	return out, func() {
		unsubscribe()
		cancel()
	}
}

// expectCaptured sends an HTTPS request to the JVM and waits for the request
// and response to come out of the subscription, with the connection's
// addresses: the kernel ties the JVM's connection to its socket.
func expectCaptured(t *testing.T, j *testJVM, out <-chan akinet.ParsedNetworkTraffic, query string) {
	t.Helper()
	var clientAddr atomic.Value
	dialer := &net.Dialer{}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dialer.DialContext(ctx, network, addr)
			if err == nil {
				clientAddr.Store(c.LocalAddr().(*net.TCPAddr))
			}
			return c, err
		},
	}}
	defer client.CloseIdleConnections()
	resp, err := client.Get("https://" + j.addr + "/hello?" + query)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != `{"hello":"jvm"}` {
		t.Fatalf("body %q", body)
	}
	// Other processes on the host netns may use libssl too: look for ours.
	var gotRequest, gotResponse bool
	deadline := time.After(10 * time.Second)
	for !gotRequest || !gotResponse {
		select {
		case pnt := <-out:
			switch c := pnt.Content.(type) {
			case akinet.HTTPRequest:
				if c.URL.Path == "/hello" && c.URL.RawQuery == query {
					gotRequest = true
					expectAddrs(t, pnt, clientAddr.Load().(*net.TCPAddr), j.addr)
				}
			case akinet.HTTPResponse:
				if c.StatusCode == 200 && strings.Contains(c.Body.String(), `"jvm"`) {
					gotResponse = true
					expectAddrs(t, pnt, mustTCPAddr(t, j.addr), clientAddr.Load().(*net.TCPAddr).String())
				}
			}
		case <-deadline:
			t.Fatalf("captured request %v, response %v", gotRequest, gotResponse)
		}
	}
}

// expectAddrs checks that pnt went from src to dst.
func expectAddrs(t *testing.T, pnt akinet.ParsedNetworkTraffic, src *net.TCPAddr, dst string) {
	t.Helper()
	want := mustTCPAddr(t, dst)
	if !pnt.SrcIP.Equal(src.IP) || pnt.SrcPort != src.Port || !pnt.DstIP.Equal(want.IP) || pnt.DstPort != want.Port {
		t.Errorf("%T from %s:%d to %s:%d, want from %s to %s",
			pnt.Content, pnt.SrcIP, pnt.SrcPort, pnt.DstIP, pnt.DstPort, src, want)
	}
}

func mustTCPAddr(t *testing.T, addr string) *net.TCPAddr {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestNodeCollectorJVMStatic: a JVM started with -javaagent. The agent is
// dormant until the subscription discovers the JVM and writes its control
// file; then the JVM's HTTPS traffic comes out of the subscription as HTTP;
// and the agent goes dormant again when the subscription ends.
func TestNodeCollectorJVMStatic(t *testing.T) {
	f := newJVMFixture(t)
	nc, ctx := javaTestCollector(t)
	j := f.start(t, 1000, nil, "-javaagent:"+f.agentJar)
	j.waitLog(t, "dormant, not capturing: no control file", 10*time.Second)

	out, unsubscribe := subscribe(t, ctx, nc, nil)
	// The agent checks its control file every 5 s.
	j.waitLog(t, "capturing HTTPS traffic", 15*time.Second)
	expectCaptured(t, j, out, "from=static")

	// The pod is no longer monitored: the agent is told to go dormant now,
	// not when the file goes stale.
	unsubscribe()
	j.waitLog(t, "dormant, not capturing: disabled by the Insights agent", 15*time.Second)
}

// TestNodeCollectorJVMBlockingClient: a JVM's blocking HTTPS client
// (HttpsURLConnection, on the JDK's SSLSocket) is captured, its requests
// with the addresses of the connection they went over.
func TestNodeCollectorJVMBlockingClient(t *testing.T) {
	f := newJVMFixture(t)
	nc, ctx := javaTestCollector(t)

	// The client connections the server accepted, recorded at accept: before
	// the handshake, so before the client can send a request on one.
	var mu sync.Mutex
	clients := map[string]bool{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"hello":"client"}`)
	}))
	srv.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateNew {
			mu.Lock()
			clients[c.RemoteAddr().String()] = true
			mu.Unlock()
		}
	}
	srv.StartTLS()
	defer srv.Close()

	out, unsubscribe := subscribe(t, ctx, nc, nil)
	defer unsubscribe()
	j := f.startClient(t, 1000, srv.URL+"/client", "-javaagent:"+f.agentJar)
	j.waitLog(t, "capturing HTTPS traffic", 15*time.Second)

	deadline := time.After(15 * time.Second)
	for {
		select {
		case pnt := <-out:
			req, ok := pnt.Content.(akinet.HTTPRequest)
			if !ok || req.URL.Path != "/client" {
				continue
			}
			src := (&net.TCPAddr{IP: pnt.SrcIP, Port: pnt.SrcPort}).String()
			mu.Lock()
			seen := clients[src]
			mu.Unlock()
			if !seen {
				t.Fatalf("request from %s, which the server never saw a connection from", src)
			}
			expectAddrs(t, pnt, &net.TCPAddr{IP: pnt.SrcIP, Port: pnt.SrcPort}, srv.Listener.Addr().String())
			return
		case <-deadline:
			t.Fatalf("no request from the JVM's client captured; JVM stdout:\n%s", j.stdout)
		}
	}
}

// TestNodeCollectorJVMControlFrames: a real JVM's agent reaches the pod's
// adapter through the kernel with HEARTBEAT and CLOSE frames. Its first
// heartbeat, sent as it starts, counts it as alive; when a connection closes,
// its CLOSE frees the connection at once rather than after the flows' idle
// timeout.
func TestNodeCollectorJVMControlFrames(t *testing.T) {
	f := newJVMFixture(t)
	nc, ctx := javaTestCollector(t)

	// Subscribed before the JVM starts, so the heartbeat it sends at start
	// comes from an allowed netns.
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	out := make(chan akinet.ParsedNetworkTraffic, 64)
	disco := discovery.WatchWith(subCtx, discovery.WatchOpts{
		Interval:         200 * time.Millisecond,
		ProcRoot:         "/proc",
		NetnsInodeFilter: ownNetns(t),
		JVMs:             true,
	})
	unsubscribe, adapter := nc.Subscribe(subCtx, disco, httpSelector(t), out, "", ownNetns(t), nil)
	defer unsubscribe()

	j := f.start(t, 1000, nil, "-javaagent:"+f.agentJar)
	deadline := time.Now().Add(10 * time.Second)
	for adapter.Stats().JavaAgentsAlive != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("the JVM's agent was not heard from: %+v", adapter.Stats())
		}
		time.Sleep(50 * time.Millisecond)
	}

	// The agent checks its control file every 5 s.
	j.waitLog(t, "capturing HTTPS traffic", 15*time.Second)
	// No keep-alive: the client closes the connection after the response,
	// and the server's engine closes with it.
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}}
	before := javaCounter(t, nc, loader.JavaCounterControlFrames)
	resp, err := client.Get("https://" + j.addr + "/hello?close=1")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	for got := 0; got < 2; {
		select {
		case <-out:
			got++
		case <-time.After(10 * time.Second):
			t.Fatalf("captured %d of the request and response", got)
		}
	}
	// Well before the 30 s idle timeout.
	deadline = time.Now().Add(5 * time.Second)
	for {
		flows, _ := adapter.Snapshot()
		if flows == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d flows left after the connection closed (control frames +%d)",
				flows, javaCounter(t, nc, loader.JavaCounterControlFrames)-before)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if javaCounter(t, nc, loader.JavaCounterControlFrames) == before {
		t.Fatal("no CLOSE frame reached the kernel")
	}
}

// TestNodeCollectorJVMJavaOff: an Insights agent with Java capture off
// (--https-libraries=openssl) switches off the Java agent an earlier Insights
// agent left capturing, at once rather than when its control file goes stale,
// and attaches nothing.
func TestNodeCollectorJVMJavaOff(t *testing.T) {
	f := newJVMFixture(t)
	j := f.start(t, 1000, nil, "-javaagent:"+f.agentJar)
	// The earlier Insights agent, killed before it could switch the agent
	// off: its control file stays enabled.
	earlier := jvm.NewController(func() javatls.Control { return javatls.Control{Enabled: true, CaptureCap: 4096} })
	earlier.Add(j.inspect(t))
	j.waitLog(t, "capturing HTTPS traffic", 15*time.Second)

	nc, ctx := testCollector(t, false)
	if nc.attacher != nil {
		t.Fatal("an attacher with Java capture off")
	}
	var counts eventCounts
	_, unsubscribe := subscribe(t, ctx, nc, counts.add)
	defer unsubscribe()
	// The agent checks its control file every 5 s; it goes stale after 60 s.
	j.waitLog(t, "dormant, not capturing: disabled by the Insights agent", 15*time.Second)
	// The pod's telemetry still shows its JVM.
	counts.wait(t, map[string]uint64{jvm.EventSeen: 1})

	// A replacement subscription for the pod, while this one still runs,
	// does not count the JVM again. Discovery scans every 200 ms.
	_, replace := subscribe(t, ctx, nc, counts.add)
	defer replace()
	time.Sleep(time.Second)
	if got := counts.get(); !maps.Equal(got, map[string]uint64{jvm.EventSeen: 1}) {
		t.Fatalf("telemetry counters %v after a replacement subscription", got)
	}
}

// TestCollectJVMJavaOff: standalone Collect with Java capture off
// (--https-libraries=openssl) also switches off a Java agent an earlier run
// left capturing, at once rather than when its control file goes stale.
func TestCollectJVMJavaOff(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF + CAP_PERFMON)")
	}
	f := newJVMFixture(t)
	j := f.start(t, 1000, nil, "-javaagent:"+f.agentJar)
	earlier := jvm.NewController(func() javatls.Control { return javatls.Control{Enabled: true, CaptureCap: 4096} })
	earlier.Add(j.inspect(t))
	j.waitLog(t, "capturing HTTPS traffic", 15*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	args := Defaults()
	args.DisableThermostat = true
	args.DiscoveryInterval = 200 * time.Millisecond
	args.FactorySelector = httpSelector(t)
	args.Out = make(chan akinet.ParsedNetworkTraffic, 64)
	done := make(chan error, 1)
	go func() { done <- Collect(ctx, args) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Collect: %v", err)
		}
	}()
	j.waitLog(t, "dormant, not capturing: disabled by the Insights agent", 15*time.Second)
}

// TestNodeCollectorJVMAttach: an unmodified JVM. The subscription discovers
// it and the attacher loads the agent into it, which then captures; a second
// attacher, as after a DaemonSet restart, finds the agent running and loads
// nothing.
func TestNodeCollectorJVMAttach(t *testing.T) {
	f := newJVMFixture(t)
	nc, ctx := javaTestCollector(t)

	for _, tc := range []struct {
		name    string
		env     []string
		jvmArgs []string
		signal  bool
	}{
		// HotSpot starts its attach listener on SIGQUIT.
		{name: "signal", signal: true},
		// With -Xrs HotSpot starts the listener at start-up, and SIGQUIT
		// would kill it: attached without a signal.
		{name: "-Xrs", jvmArgs: []string{"-Xrs"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nc.attacher = f.attacher(t)
			attachCtx, stop := context.WithCancel(ctx)
			defer stop()
			go nc.attacher.Run(attachCtx)

			j := f.start(t, 1000, tc.env, tc.jvmArgs...)
			var counts eventCounts
			out, unsubscribe := subscribe(t, ctx, nc, counts.add)
			defer unsubscribe()
			// The attacher waits until the JVM has run for 5 s.
			j.waitLog(t, "loaded (attach)", 30*time.Second)
			j.waitLog(t, "capturing HTTPS traffic", 10*time.Second)
			// The agent logs before the JVM answers the helper.
			waitStats(t, nc.attacher, func(st jvm.AttachStats) bool { return st.Attached == 1 })
			expectCaptured(t, j, out, "from="+strings.TrimPrefix(tc.name, "-"))
			// The pod's telemetry shows the JVM and its attach.
			counts.wait(t, map[string]uint64{jvm.EventSeen: 1, jvm.EventAttached: 1})
			if strings.Contains(j.stdout.String(), "Full thread dump") {
				t.Error("the attach printed a thread dump into the application's output")
			}

			// A restarted DaemonSet attaches nothing.
			again := f.attacher(t)
			go again.Run(attachCtx)
			again.Add(j.inspect(t), nil)
			waitStats(t, again, func(st jvm.AttachStats) bool { return st.AlreadyRunning == 1 })
			if n := strings.Count(j.stderr.String(), "loaded (attach)"); n != 1 {
				t.Errorf("agent loaded %d times", n)
			}
		})
	}
}

// TestNodeCollectorJVMAttachInProgress: while another attach owns the JVM's
// trigger file (an Insights agent being replaced, or jcmd), the attacher does
// not signal the JVM, since a second SIGQUIT could print a thread dump; it
// retries, and attaches once the trigger is gone.
func TestNodeCollectorJVMAttachInProgress(t *testing.T) {
	f := newJVMFixture(t)
	nc, ctx := javaTestCollector(t)
	j := f.start(t, 1000, nil)
	p := j.inspect(t)
	trigger := filepath.Join("/proc", strconv.Itoa(int(p.PID)), "root", "tmp", ".attach_pid"+strconv.Itoa(int(p.NSPID)))
	if err := os.WriteFile(trigger, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(trigger, 1000, 1000); err != nil {
		t.Fatal(err)
	}

	nc.attacher = f.attacher(t)
	go nc.attacher.Run(ctx)
	_, unsubscribe := subscribe(t, ctx, nc, nil)
	defer unsubscribe()
	// 5 s until the JVM is old enough, then up to 10 s waiting for the
	// other attach's listener.
	time.Sleep(17 * time.Second)
	if st := nc.attacher.Stats(); st.Attached != 0 || len(st.Failed) != 0 {
		t.Fatalf("attacher stats %+v while another attach owned the trigger", st)
	}
	if strings.Contains(j.stdout.String(), "Full thread dump") || strings.Contains(j.stderr.String(), "postman-insights-agent") {
		t.Fatal("the JVM was signalled or attached")
	}

	// The other attach gave up: the retry, 30 s after the first try, signals.
	if err := os.Remove(trigger); err != nil {
		t.Fatal(err)
	}
	waitStatsFor(t, nc.attacher, 45*time.Second, func(st jvm.AttachStats) bool { return st.Attached == 1 })
	if strings.Contains(j.stdout.String(), "Full thread dump") {
		t.Error("the attach printed a thread dump into the application's output")
	}
}

// TestNodeCollectorJVMAttachDisabled: a JVM with attach disabled where its
// command line does not show it is never signalled: a signal would print a
// thread dump into its log.
func TestNodeCollectorJVMAttachDisabled(t *testing.T) {
	f := newJVMFixture(t)
	argFile := filepath.Join(f.dir, "jvm.args")
	if err := os.WriteFile(argFile, []byte("-XX:+DisableAttachMechanism\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		uid     int
		env     []string
		jvmArgs []string
	}{
		// Read from the JVM's environment: uid 1000 has no user name here,
		// so HotSpot publishes no perf data.
		{name: "JAVA_TOOL_OPTIONS", uid: 1000, env: []string{"JAVA_TOOL_OPTIONS=-XX:+DisableAttachMechanism"}},
		// Only HotSpot's perf data shows flags from an argument file.
		{name: "argument file", uid: 65534, jvmArgs: []string{"@" + argFile}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.jvmArgs) > 0 && f.jdk8() {
				t.Skip("JDK 8 has no argument files")
			}
			nc, ctx := javaTestCollector(t)
			nc.attacher = f.attacher(t)
			go nc.attacher.Run(ctx)

			j := f.start(t, tc.uid, tc.env, tc.jvmArgs...)
			_, unsubscribe := subscribe(t, ctx, nc, nil)
			defer unsubscribe()
			waitStats(t, nc.attacher, func(st jvm.AttachStats) bool { return st.Skipped[jvm.SkipAttachDisabled] == 1 })
			time.Sleep(time.Second)
			if strings.Contains(j.stdout.String(), "Full thread dump") || strings.Contains(j.stderr.String(), "postman-insights-agent") {
				t.Error("the JVM was signalled or attached")
			}
		})
	}
}

// waitStats waits until the attacher's counters satisfy ok.
func waitStats(t *testing.T, a *jvm.Attacher, ok func(jvm.AttachStats) bool) {
	t.Helper()
	waitStatsFor(t, a, 30*time.Second, ok)
}

// waitStatsFor is waitStats with a deadline d away.
func waitStatsFor(t *testing.T, a *jvm.Attacher, d time.Duration, ok func(jvm.AttachStats) bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok(a.Stats()) {
		if time.Now().After(deadline) {
			t.Fatalf("attacher stats %+v", a.Stats())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// jdk8 reports whether the fixture's JDK is JDK 8.
func (f *jvmFixture) jdk8() bool {
	release, _ := os.ReadFile(filepath.Join(f.javaHome, "release"))
	return strings.Contains(string(release), `JAVA_VERSION="1.8`)
}

// inspect returns the test JVM as discovery reports it.
func (j *testJVM) inspect(t *testing.T) *jvm.Process {
	t.Helper()
	// unshare and sh exec the JVM, so it keeps their PID.
	p, err := jvm.Inspect("/proc", uint32(j.cmd.Process.Pid), nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// eventCounts records telemetry counters.
type eventCounts struct {
	mu     sync.Mutex
	counts map[string]uint64
}

func (c *eventCounts) add(event string, n uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts == nil {
		c.counts = make(map[string]uint64)
	}
	c.counts[event] += n
}

func (c *eventCounts) get() map[string]uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return maps.Clone(c.counts)
}

// wait waits until the counters are want: the attacher reports just after
// it counts.
func (c *eventCounts) wait(t *testing.T, want map[string]uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !maps.Equal(c.get(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("telemetry counters %v, want %v", c.get(), want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
