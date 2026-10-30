// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	"golang.org/x/sys/unix"

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
//	POSTMAN_TEST_AGENT_JAR  java-agent/build/agent/postman-insights-java-agent.jar
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
        for (int n = 0;; n++) {
            HttpsURLConnection c = (HttpsURLConnection) new java.net.URL(url + "?n=" + n).openConnection();
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
	f := &jvmFixture{javaHome: javaHome, dir: dir, agentJar: filepath.Join(dir, "postman-insights-java-agent.jar"), keystore: filepath.Join(dir, "server.p12")}
	for name, content := range map[string][]byte{
		"Server.java":                            []byte(jvmServer),
		"postman-insights-java-agent.jar":        jar,
		"postman-insights-java-agent.jar.sha256": []byte(hex.EncodeToString(sum[:]) + "  postman-insights-java-agent.jar\n"),
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
	return newTestAttacher(t, f.helper(t), f.agentJar)
}

// helper builds the attach helper, once per fixture, and returns its path.
func (f *jvmFixture) helper(t *testing.T) string {
	t.Helper()
	helper := filepath.Join(f.dir, "postman-insights-jvm-attach")
	if _, err := os.Stat(helper); err != nil {
		build := exec.Command("go", "build", "-o", helper, "github.com/postmanlabs/postman-insights-agent/cmd/postman-insights-jvm-attach")
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build the attach helper: %v\n%s", err, out)
		}
	}
	return helper
}

func newTestAttacher(t *testing.T, helper, agentJar string) *jvm.Attacher {
	t.Helper()
	a, err := jvm.NewAttacher(jvm.AttacherConfig{
		HelperPath:   helper,
		JarPath:      agentJar,
		ChecksumPath: agentJar + ".sha256",
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
	return f.startMain(t, uid, env, f.dir, "Server", []string{f.keystore}, jvmArgs...)
}

// startClient starts a JVM running the blocking HTTPS client, requesting url.
func (f *jvmFixture) startClient(t *testing.T, uid int, url string, jvmArgs ...string) *testJVM {
	t.Helper()
	return f.startMain(t, uid, nil, f.dir, "Server", []string{"client", url}, jvmArgs...)
}

// startApp starts one of the framework test apps (java-agent/src/testApps),
// a server or, with url, a client. Skipped unless POSTMAN_TEST_APPS_DIR names
// their build (gradlew testAppsDist: java-agent/build/test-apps).
func (f *jvmFixture) startApp(t *testing.T, app, url string, jvmArgs ...string) *testJVM {
	t.Helper()
	dir := os.Getenv("POSTMAN_TEST_APPS_DIR")
	if dir == "" {
		t.Skip("set POSTMAN_TEST_APPS_DIR to run the framework apps")
	}
	args := []string{app, f.keystore}
	if url != "" {
		args = append(args, url)
	}
	return f.startMain(t, 1000, nil, filepath.Join(dir, "*"), "com.postman.insights.testapps.Main", args, jvmArgs...)
}

// startMain starts mainClass with mainArgs and waits until it says it is
// listening (a server, whose address it records) or started (a client).
func (f *jvmFixture) startMain(t *testing.T, uid int, env []string, classpath, mainClass string, mainArgs []string, jvmArgs ...string) *testJVM {
	t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	id := strconv.Itoa(uid)
	args := append([]string{"--mount", "--propagation", "private", "sh", "-ec",
		`mount -t tmpfs tmpfs /tmp
exec setpriv --reuid "$0" --regid "$0" --clear-groups "$@"`, id,
		filepath.Join(f.javaHome, "bin", "java")}, jvmArgs...)
	args = append(append(args, "-cp", classpath, mainClass), mainArgs...)
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
	// Other processes on the host netns may use libssl too: look for ours,
	// the request by its query and the response by its connection. Each
	// must come out once: not also through the libssl uprobes, nor twice
	// through nested hooks.
	from := clientAddr.Load().(*net.TCPAddr)
	expectOnce(t, out, func(pnt akinet.ParsedNetworkTraffic) (request, response bool) {
		switch c := pnt.Content.(type) {
		case akinet.HTTPRequest:
			if c.URL.Path == "/hello" && c.URL.RawQuery == query {
				expectAddrs(t, pnt, from, j.addr)
				return true, false
			}
		case akinet.HTTPResponse:
			if pnt.DstPort == from.Port && pnt.DstIP.Equal(from.IP) {
				expectAddrs(t, pnt, mustTCPAddr(t, j.addr), from.String())
				if c.StatusCode != 200 || !strings.Contains(c.Body.String(), `"jvm"`) {
					t.Errorf("response %d %q", c.StatusCode, c.Body.String())
				}
				return false, true
			}
		}
		return false, false
	})
}

// expectOnce reads out until match has found a request and a response, and
// a second more, and fails unless each came exactly once.
func expectOnce(t *testing.T, out <-chan akinet.ParsedNetworkTraffic,
	match func(akinet.ParsedNetworkTraffic) (request, response bool)) {
	t.Helper()
	var requests, responses int
	deadline := time.After(10 * time.Second)
	var settle <-chan time.Time
	for {
		select {
		case pnt := <-out:
			req, resp := match(pnt)
			if req {
				requests++
			}
			if resp {
				responses++
			}
			if requests > 1 || responses > 1 {
				t.Fatalf("captured %d requests and %d responses, want one each", requests, responses)
			}
			if requests == 1 && responses == 1 && settle == nil {
				settle = time.After(time.Second)
			}
		case <-settle:
			return
		case <-deadline:
			t.Fatalf("captured %d requests and %d responses, want one each", requests, responses)
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

	srv, accepted := acceptRecordingServer(t)
	out, unsubscribe := subscribe(t, ctx, nc, nil)
	defer unsubscribe()
	j := f.startClient(t, 1000, srv.URL+"/client", "-javaagent:"+f.agentJar)
	j.waitLog(t, "capturing HTTPS traffic", 15*time.Second)
	expectClientRequest(t, j, out, srv, accepted)
}

// acceptRecordingServer starts an HTTPS server for /client, answering
// /client?n=N with {"n":N}, and returns the client addresses it accepted
// connections from, recorded at accept: before the handshake, so before a
// client can send a request on one.
func acceptRecordingServer(t *testing.T) (*httptest.Server, func(addr string) bool) {
	t.Helper()
	var mu sync.Mutex
	clients := map[string]bool{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"n":`+strconv.Quote(r.URL.Query().Get("n"))+`}`)
	}))
	srv.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateNew {
			mu.Lock()
			clients[c.RemoteAddr().String()] = true
			mu.Unlock()
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, func(addr string) bool {
		mu.Lock()
		defer mu.Unlock()
		return clients[addr]
	}
}

// expectClientRequest takes the first request the JVM's client sent to srv
// (it sends /client?n=0, n=1, ... every 200 ms) and checks that it, and its
// response, came out once each, with the addresses of a connection srv
// accepted, reversed for the response.
func expectClientRequest(t *testing.T, j *testJVM, out <-chan akinet.ParsedNetworkTraffic,
	srv *httptest.Server, accepted func(string) bool) {
	t.Helper()
	server := srv.Listener.Addr().String()
	var n string
	var client *net.TCPAddr
	expectOnce(t, out, func(pnt akinet.ParsedNetworkTraffic) (request, response bool) {
		switch c := pnt.Content.(type) {
		case akinet.HTTPRequest:
			if c.URL.Path != "/client" || (n != "" && c.URL.Query().Get("n") != n) {
				return false, false
			}
			if n == "" {
				n = c.URL.Query().Get("n")
				client = &net.TCPAddr{IP: pnt.SrcIP, Port: pnt.SrcPort}
				if !accepted(client.String()) {
					t.Fatalf("request from %s, which the server never accepted a connection from", client)
				}
			}
			expectAddrs(t, pnt, client, server)
			return true, false
		case akinet.HTTPResponse:
			if n == "" || c.Body.String() != `{"n":`+strconv.Quote(n)+`}` {
				return false, false
			}
			expectAddrs(t, pnt, mustTCPAddr(t, server), client.String())
			return false, true
		}
		return false, false
	})
	if t.Failed() {
		t.Logf("JVM stdout:\n%s", j.stdout)
	}
}

// TestNodeCollectorJVMFrameworks: the HTTPS servers and clients of the
// frameworks customers run are captured, with their connections' addresses:
// each reads its socket and unwraps on the same thread, which the kernel's
// tie relies on. Each JVM loads the agent with -javaagent.
func TestNodeCollectorJVMFrameworks(t *testing.T) {
	f := newJVMFixture(t)
	nc, ctx := javaTestCollector(t)
	for _, app := range []struct {
		name    string
		minJava int
	}{
		{"netty-jdk", 8},
		{"netty-openssl", 8},
		{"netty-epoll", 8},
		{"tomcat", 17},
		{"jetty", 17},
		{"undertow", 17},
	} {
		t.Run(app.name, func(t *testing.T) {
			if f.javaMajor() < app.minJava {
				t.Skipf("needs Java %d", app.minJava)
			}
			out, unsubscribe := subscribe(t, ctx, nc, nil)
			defer unsubscribe()
			j := f.startApp(t, app.name, "", "-javaagent:"+f.agentJar)
			j.waitLog(t, "capturing HTTPS traffic", 15*time.Second)
			// Once each: not also through the libssl uprobes (Netty's
			// BoringSSL is its own library), nor twice through nested hooks.
			expectCaptured(t, j, out, "from="+app.name)
		})
	}
}

// TestNodeCollectorJVMFrameworksBurst: concurrent curl clients, one request
// per connection, as the kind end-to-end test sends them. Every request and
// response carries its own connection's addresses. Tomcat often reads the
// handshake's last flight and the request on one worker thread and unwraps
// the request on another, whose last read was another connection's socket:
// the kernel counts that (java_conn_handoffs), and the connection keeps the
// addresses its handshake tied it to. (Go's TLS client does not get Tomcat
// to do that.)
func TestNodeCollectorJVMFrameworksBurst(t *testing.T) {
	f := newJVMFixture(t)
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not found")
	}
	// Without the libssl uprobes, which would capture curl's side too.
	nc, ctx := testCollectorWith(t, NodeCollectorConfig{EnableJava: true, DisableOpenSSL: true})
	if !nc.Loader().JavaEnabled() {
		t.Fatalf("Java TLS programs did not load: %v", nc.Loader().JavaError())
	}
	counter := func(idx uint32) uint64 {
		t.Helper()
		v, err := nc.Loader().ReadJavaCounter(idx)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, app := range []struct {
		name    string
		minJava int
	}{
		{"netty-jdk", 8},
		{"netty-openssl", 8},
		{"netty-epoll", 8},
		{"tomcat", 17},
		{"jetty", 17},
		{"undertow", 17},
	} {
		t.Run(app.name, func(t *testing.T) {
			if f.javaMajor() < app.minJava {
				t.Skipf("needs Java %d", app.minJava)
			}
			out, unsubscribe := subscribe(t, ctx, nc, nil)
			defer unsubscribe()
			j := f.startApp(t, app.name, "", "-javaagent:"+f.agentJar)
			j.waitLog(t, "capturing HTTPS traffic", 15*time.Second)
			handoffs, unbound := counter(loader.JavaCounterConnHandoff), counter(loader.JavaCounterConnUnbound)

			// Each request has its own id; curl reports the port it sent it
			// from, the ground truth for the addresses of its connection.
			const clients, connsPerClient = 8, 9
			var mu sync.Mutex
			portOf := map[string]int{} // request id to client port
			var wg sync.WaitGroup
			for c := range clients {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := range connsPerClient {
						id := fmt.Sprintf("%d-%d", c, i)
						got, err := exec.Command("curl", "-fsSk", "-o", "/dev/null", "-w", "%{local_port}",
							"https://"+j.addr+"/hello?burst="+id).Output()
						port, perr := strconv.Atoi(string(got))
						if err != nil || perr != nil {
							t.Errorf("curl: %v %q", err, got)
							return
						}
						mu.Lock()
						portOf[id] = port
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			if t.Failed() {
				return
			}
			ports := map[int]bool{}
			for _, port := range portOf {
				ports[port] = true
			}

			srv := mustTCPAddr(t, j.addr)
			requests, responses := map[int]int{}, map[int]int{}
			deadline := time.After(15 * time.Second)
			for len(requests) < len(ports) || len(responses) < len(ports) {
				select {
				case pnt := <-out:
					switch c := pnt.Content.(type) {
					case akinet.HTTPRequest:
						port, ok := portOf[c.URL.Query().Get("burst")]
						if c.URL.Path != "/hello" || !ok {
							continue // not this test's
						}
						if pnt.SrcPort != port || pnt.DstPort != srv.Port {
							t.Errorf("request of the client on port %d went from port %d to port %d, want to %d",
								port, pnt.SrcPort, pnt.DstPort, srv.Port)
						}
						requests[port]++
					case akinet.HTTPResponse:
						if pnt.SrcPort != srv.Port || !ports[pnt.DstPort] {
							continue
						}
						responses[pnt.DstPort]++
					}
				case <-deadline:
					t.Fatalf("captured requests of %d and responses to %d of %d connections",
						len(requests), len(responses), len(ports))
				}
			}
			for port := range ports {
				if requests[port] != 1 || responses[port] != 1 {
					t.Errorf("client port %d: %d requests and %d responses, want one each",
						port, requests[port], responses[port])
				}
			}
			if got := counter(loader.JavaCounterConnUnbound) - unbound; got != 0 {
				t.Errorf("conn_unbound grew by %d, want 0", got)
			}
			got := counter(loader.JavaCounterConnHandoff) - handoffs
			t.Logf("conn_handoffs grew by %d over %d connections", got, len(ports))
			// Otherwise the burst did not exercise what it is for.
			if app.name == "tomcat" && got == 0 {
				t.Error("conn_handoffs did not grow: Tomcat unwrapped every request on the thread that read it")
			}
		})
	}
}

// TestNodeCollectorJVMHttpClient: the JDK's HttpClient (java.net.http).
func TestNodeCollectorJVMHttpClient(t *testing.T) {
	f := newJVMFixture(t)
	if f.javaMajor() < 17 {
		t.Skip("needs Java 17")
	}
	nc, ctx := javaTestCollector(t)
	srv, accepted := acceptRecordingServer(t)
	out, unsubscribe := subscribe(t, ctx, nc, nil)
	defer unsubscribe()
	j := f.startApp(t, "jdk-httpclient", srv.URL+"/client",
		"-javaagent:"+f.agentJar, "-Djdk.internal.httpclient.disableHostnameVerification=true")
	j.waitLog(t, "capturing HTTPS traffic", 15*time.Second)
	expectClientRequest(t, j, out, srv, accepted)
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
	if strings.Contains(j.stdout.String(), "Full thread dump") || strings.Contains(j.stderr.String(), "postman-insights-java-agent") {
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
			if strings.Contains(j.stdout.String(), "Full thread dump") || strings.Contains(j.stderr.String(), "postman-insights-java-agent") {
				t.Error("the JVM was signalled or attached")
			}
		})
	}
}

// daemonSetCapabilities are the only capabilities of the DaemonSet's agent
// container, which drops ALL: the released manifest's, and SETUID and SETGID
// for the attach helper (plan 5.1). Neither DAC_OVERRIDE nor DAC_READ_SEARCH
// is among them, so root cannot read files that only a JVM's user may read.
var daemonSetCapabilities = []string{"net_raw", "sys_ptrace", "sys_admin", "bpf", "perfmon", "setuid", "setgid"}

// The environment of TestAttachChild, which TestNodeCollectorJVMAttachDAC
// runs in a copy of this test binary with only daemonSetCapabilities.
const (
	attachChildPID    = "POSTMAN_TEST_ATTACH_CHILD_PID"
	attachChildHelper = "POSTMAN_TEST_ATTACH_CHILD_HELPER"
	attachChildJar    = "POSTMAN_TEST_ATTACH_CHILD_JAR"
	attachChildStats  = "attach stats: "
)

// TestNodeCollectorJVMAttachDAC attaches with the DaemonSet's capabilities
// only, to a JVM of another user that publishes perf data (uid 65534, which
// has a user name) and to one that does not (-XX:-UsePerfData): the attacher
// reads the JVM's perf data (0600) or environment (0400) through the helper,
// as the JVM's user.
func TestNodeCollectorJVMAttachDAC(t *testing.T) {
	f := newJVMFixture(t)
	helper := f.helper(t)
	for _, tc := range []struct {
		name     string
		uid      int
		jvmArgs  []string
		perfData bool
	}{
		{name: "perf data", uid: 65534, perfData: true},
		// Off explicitly, whether or not the host has a user name for the uid.
		{name: "environment", uid: 1000, jvmArgs: []string{"-XX:-UsePerfData"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := f.start(t, tc.uid, []string{"JAVA_TOOL_OPTIONS=-Dpostman.test=dac"}, tc.jvmArgs...)
			p := j.inspect(t)
			perfFiles, _ := filepath.Glob(filepath.Join("/proc", strconv.Itoa(int(p.PID)), "root", "tmp", "hsperfdata_*", strconv.Itoa(int(p.NSPID))))
			if got := len(perfFiles) > 0; got != tc.perfData {
				t.Fatalf("the JVM publishes perf data: %v, want %v", got, tc.perfData)
			}
			cmd := exec.Command("setpriv", "--bounding-set=-all,+"+strings.Join(daemonSetCapabilities, ",+"),
				"--inh-caps=-all", "--", os.Args[0], "-test.run=^TestAttachChild$", "-test.count=1")
			cmd.Env = append(os.Environ(),
				attachChildPID+"="+strconv.Itoa(j.cmd.Process.Pid),
				attachChildHelper+"="+helper,
				attachChildJar+"="+f.agentJar)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("attach child: %v\n%s", err, out)
			}
			_, line, ok := strings.Cut(string(out), attachChildStats)
			if !ok {
				t.Fatalf("attach child printed no stats:\n%s", out)
			}
			line, _, _ = strings.Cut(line, "\n")
			var st jvm.AttachStats
			if err := json.Unmarshal([]byte(line), &st); err != nil {
				t.Fatal(err)
			}
			if st.Attached != 1 {
				t.Fatalf("attacher stats %+v\n%s", st, out)
			}
			j.waitLog(t, "loaded (attach)", 10*time.Second)
		})
	}
}

// TestAttachChild attaches to one JVM and prints the attacher's stats. Only
// TestNodeCollectorJVMAttachDAC runs it, with a reduced capability set.
func TestAttachChild(t *testing.T) {
	pid, err := strconv.ParseUint(os.Getenv(attachChildPID), 10, 32)
	if err != nil {
		t.Skip("run by TestNodeCollectorJVMAttachDAC")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, capability := range []uint{unix.CAP_DAC_OVERRIDE, unix.CAP_DAC_READ_SEARCH} {
		if effectiveCapability(t, status, capability) {
			t.Fatalf("capability %d is effective; the test needs it dropped", capability)
		}
	}
	a := newTestAttacher(t, os.Getenv(attachChildHelper), os.Getenv(attachChildJar))
	p, err := jvm.Inspect("/proc", uint32(pid), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Run(ctx)
	a.Add(p, nil)
	// The attacher waits until the JVM has run for 5 s; an inspect failure
	// is retried after 30 s.
	deadline := time.Now().Add(25 * time.Second)
	for st := a.Stats(); st.Attached+st.AlreadyRunning == 0 && len(st.Failed)+len(st.Skipped) == 0; st = a.Stats() {
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	b, err := json.Marshal(a.Stats())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(attachChildStats + string(b))
}

// effectiveCapability reports whether /proc/<pid>/status content shows
// capability in the effective set.
func effectiveCapability(t *testing.T, status []byte, capability uint) bool {
	t.Helper()
	m := regexp.MustCompile(`(?m)^CapEff:\s*([0-9a-f]+)$`).FindSubmatch(status)
	if m == nil {
		t.Fatal("no CapEff in status")
	}
	mask, err := strconv.ParseUint(string(m[1]), 16, 64)
	if err != nil {
		t.Fatal(err)
	}
	return mask&(1<<capability) != 0
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
	return f.javaMajor() == 8
}

// javaMajor returns the JDK's feature release: 8, 17, 25.
func (f *jvmFixture) javaMajor() int {
	release, _ := os.ReadFile(filepath.Join(f.javaHome, "release"))
	m := regexp.MustCompile(`JAVA_VERSION="(?:1\.)?(\d+)`).FindSubmatch(release)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(string(m[1]))
	return n
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
