//go:build linux

package jvm

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/postmanlabs/postman-insights-agent/ebpf/javatls"
)

// TestAttacherJVMRollout: two Insights agents run on a node at once, as in a
// DaemonSet rollout with maxSurge above 0, and attach two JVMs that share a
// /tmp (one container, or a pod's containers sharing an emptyDir). The old
// agent has staged its copy for one JVM and not attached yet when the new
// agent attaches the other JVM and removes copies.
//
//   - The new agent keeps the old one's copy, staged less than stagingGrace
//     ago, so the old agent's attach goes through as staged.
//   - Against a new agent that removes young copies (as Insights agents from
//     before stagingGrace do), the old agent's attach finds its copy gone,
//     stages it again and attaches on its one retry.
//
// It needs real JVMs: POSTMAN_TEST_JAVA_HOME and POSTMAN_TEST_AGENT_JAR, and
// root for the mount namespace.
func TestAttacherJVMRollout(t *testing.T) {
	javaHome, agentJar := os.Getenv("POSTMAN_TEST_JAVA_HOME"), os.Getenv("POSTMAN_TEST_AGENT_JAR")
	if javaHome == "" || agentJar == "" {
		t.Skip("set POSTMAN_TEST_JAVA_HOME and POSTMAN_TEST_AGENT_JAR to run")
	}
	if _, err := exec.LookPath("setpriv"); err != nil {
		t.Skip("setpriv not found")
	}
	fx := newRolloutFixture(t, javaHome, agentJar)

	for _, tc := range []struct {
		name string
		// legacyRemover makes the new agent remove young copies too.
		legacyRemover bool
	}{
		{name: "young copy kept"},
		{name: "young copy removed by a legacy agent", legacyRemover: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := startContainer(t) // the /tmp both JVMs share
			first, second := fx.startJVM(t, c), fx.startJVM(t, c)
			agentDir := filepath.Join("/proc", strconv.Itoa(int(c.PID)), "root", agentDirParent, agentDirName)
			// The attacher waits until a JVM has run for minAge.
			time.Sleep(minAge)

			oldAgent := fx.attacher(t, fx.oldJar)
			paused := &pauseAfterStage{attachOps: oldAgent.ops, staged: make(chan struct{}), release: make(chan struct{})}
			oldAgent.ops = paused
			newAgent := fx.attacher(t, fx.newJar)
			if tc.legacyRemover {
				newAgent.ops = legacyRemover{newAgent.ops}
			}

			// The old agent stages its copy for the first JVM, and waits.
			p := first.process(t)
			oldAgent.Add(p, nil)
			oldState := oldAgent.next(oldAgent.now())
			require.NotNil(t, oldState)
			oldDone := make(chan *attachState)
			go func() {
				oldAgent.try(context.Background(), oldState)
				oldDone <- oldState
			}()
			select {
			case <-paused.staged:
			case <-time.After(time.Minute):
				t.Fatal("the old agent did not stage its copy")
			}
			require.DirExists(t, filepath.Join(agentDir, oldAgent.jarDir))

			// The new agent attaches the second JVM, and removes the
			// copies it may.
			s := attempt(t, newAgent, second.process(t))
			require.True(t, s.done)
			require.Equal(t, uint64(1), newAgent.Stats().Attached, "new agent: %+v\n%s", newAgent.Stats(), second.stderr)
			if tc.legacyRemover {
				assert.NoDirExists(t, filepath.Join(agentDir, oldAgent.jarDir), "the legacy remover kept the old copy")
			} else {
				assert.DirExists(t, filepath.Join(agentDir, oldAgent.jarDir), "the new agent removed a copy staged just now")
			}

			// The old agent attaches the first JVM.
			close(paused.release)
			select {
			case s = <-oldDone:
			case <-time.After(2 * time.Minute):
				t.Fatal("the old agent's attach did not end")
			}
			require.True(t, s.done)
			st := oldAgent.Stats()
			assert.Equal(t, uint64(1), st.Attached, "old agent: %+v\n%s", st, first.stderr)
			assert.Empty(t, st.Failed, "old agent")
			wantStages := 1
			if tc.legacyRemover {
				wantStages = 2 // staged again for the retry
			}
			assert.Equal(t, wantStages, paused.stages(), "old agent's stagings")

			first.waitLog(t, "version 0.0.0-old loaded (attach)")
			second.waitLog(t, "loaded (attach)")
			assert.NotContains(t, second.stderr.String(), "0.0.0-old", "the second JVM loaded the old agent")
			// Each JVM keeps the copy it loaded; both stay.
			names := entries(t, agentDir)
			assert.Contains(t, names, oldAgent.jarDir)
			assert.Contains(t, names, newAgent.jarDir)
		})
	}
}

// pauseAfterStage stops the attach after its first staging until release is
// closed.
type pauseAfterStage struct {
	attachOps
	staged, release chan struct{}

	mu sync.Mutex
	n  int
}

func (p *pauseAfterStage) stage(proc *Process, jar []byte, dirName string, now time.Time) (string, error) {
	path, err := p.attachOps.stage(proc, jar, dirName, now)
	p.mu.Lock()
	p.n++
	first := p.n == 1
	p.mu.Unlock()
	if first {
		close(p.staged)
		<-p.release
	}
	return path, err
}

func (p *pauseAfterStage) stages() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n
}

// legacyRemover removes copies however young, as Insights agents from before
// stagingGrace do.
type legacyRemover struct{ attachOps }

func (l legacyRemover) removeStaleCopies(p *Process, keep string, _ time.Time) (cleanupResult, error) {
	return l.attachOps.removeStaleCopies(p, keep, time.Now().Add(time.Hour))
}

type rolloutFixture struct {
	javaHome, dir, helper, newJar, oldJar string
}

func newRolloutFixture(t *testing.T, javaHome, agentJar string) *rolloutFixture {
	t.Helper()
	// Outside /tmp, which each container replaces; readable by the JVMs'
	// user.
	dir, err := os.MkdirTemp("/var/tmp", "attacher-jvm-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	require.NoError(t, os.Chmod(dir, 0o755))
	fx := &rolloutFixture{javaHome: javaHome, dir: dir, helper: filepath.Join(dir, "postman-insights-jvm-attach")}

	build := exec.Command("go", "build", "-o", fx.helper, "github.com/postmanlabs/postman-insights-agent/cmd/postman-insights-jvm-attach")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := build.CombinedOutput()
	require.NoError(t, err, "build the attach helper: %s", out)

	jar, err := os.ReadFile(agentJar)
	require.NoError(t, err)
	fx.newJar = writeJar(t, filepath.Join(dir, "new"), jar)
	fx.oldJar = writeJar(t, filepath.Join(dir, "old"), withVersion(t, jar, "0.0.0-old"))

	src := filepath.Join(dir, "Idle.java")
	require.NoError(t, os.WriteFile(src, []byte(`public class Idle {
    public static void main(String[] args) throws Exception {
        System.out.println("ready");
        Thread.sleep(600000);
    }
}
`), 0o644))
	out, err = exec.Command(filepath.Join(javaHome, "bin", "javac"), "-d", dir, src).CombinedOutput()
	require.NoError(t, err, "javac: %s", out)
	require.NoError(t, os.Chmod(filepath.Join(dir, "Idle.class"), 0o644))
	return fx
}

// writeJar writes jar and its checksum in dir, and returns the jar's path.
func writeJar(t *testing.T, dir string, jar []byte) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path := filepath.Join(dir, agentJarName)
	sum := sha256.Sum256(jar)
	require.NoError(t, os.WriteFile(path, jar, 0o644))
	require.NoError(t, os.WriteFile(path+".sha256", []byte(hex.EncodeToString(sum[:])+"  "+agentJarName+"\n"), 0o644))
	return path
}

// withVersion returns jar with another Implementation-Version, as another
// Insights agent release bundles.
func withVersion(t *testing.T, jar []byte, version string) []byte {
	t.Helper()
	src, err := zip.NewReader(bytes.NewReader(jar), int64(len(jar)))
	require.NoError(t, err)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range src.File {
		if e.Name != "META-INF/MANIFEST.MF" {
			w, err := zw.CreateRaw(&e.FileHeader)
			require.NoError(t, err)
			if !e.FileInfo().IsDir() {
				r, err := e.OpenRaw()
				require.NoError(t, err)
				_, err = io.Copy(w, r)
				require.NoError(t, err)
			}
			continue
		}
		r, err := e.Open()
		require.NoError(t, err)
		manifest, err := io.ReadAll(r)
		require.NoError(t, err)
		manifest = regexp.MustCompile(`(?m)^Implementation-Version: .*$`).ReplaceAll(manifest, []byte("Implementation-Version: "+version+"\r"))
		w, err := zw.Create(e.Name)
		require.NoError(t, err)
		_, err = w.Write(manifest)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func (fx *rolloutFixture) attacher(t *testing.T, jar string) *Attacher {
	t.Helper()
	a, err := NewAttacher(AttacherConfig{
		HelperPath:   fx.helper,
		JarPath:      jar,
		ChecksumPath: jar + ".sha256",
		AgentArgs:    func() string { return javatls.ArgCaptureCap + "=16384" },
	})
	require.NoError(t, err)
	return a
}

// rolloutJVM is an idle JVM in a container.
type rolloutJVM struct {
	cmd    *exec.Cmd
	stderr *lockedBuffer
}

// startJVM starts an idle JVM as uid 1000 in c's mount namespace.
func (fx *rolloutFixture) startJVM(t *testing.T, c *Process) *rolloutJVM {
	t.Helper()
	cmd := exec.Command("nsenter", "-t", strconv.Itoa(int(c.PID)), "-m",
		"setpriv", "--reuid", "1000", "--regid", "1000", "--clear-groups",
		filepath.Join(fx.javaHome, "bin", "java"), "-cp", fx.dir, "Idle")
	j := &rolloutJVM{cmd: cmd, stderr: &lockedBuffer{}}
	cmd.Stderr = j.stderr
	waitReady(t, cmd)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("JVM %d stderr:\n%s", cmd.Process.Pid, j.stderr)
		}
	})
	return j
}

func (j *rolloutJVM) process(t *testing.T) *Process {
	t.Helper()
	// nsenter and setpriv exec the JVM, so it keeps their PID.
	p, err := Inspect("/proc", uint32(j.cmd.Process.Pid), nil)
	require.NoError(t, err)
	return p
}

func (j *rolloutJVM) waitLog(t *testing.T, what string) {
	t.Helper()
	require.Eventually(t, func() bool { return strings.Contains(j.stderr.String(), what) },
		10*time.Second, 50*time.Millisecond, "the JVM did not log %q:\n%s", what, j.stderr)
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
