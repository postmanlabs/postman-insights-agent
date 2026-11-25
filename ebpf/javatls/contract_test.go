package javatls

import (
	"os"
	"path"
	"regexp"
	"testing"
)

// TestBuildScriptInSync checks that build-scripts/java-capture-files.sh, which
// release images and Dockerfile.ebpf build the files with, names them as the
// agent loads them, and that the Gradle build and the helper's package agree.
func TestBuildScriptInSync(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	value := func(file, re string) string {
		t.Helper()
		m := regexp.MustCompile(re).FindStringSubmatch(read(file))
		if m == nil {
			t.Fatalf("%s: no match for %s", file, re)
		}
		return m[1]
	}

	const script = "../../build-scripts/java-capture-files.sh"
	jar := value(script, `(?m)^JAR_NAME=(\S+)$`)
	helper := value(script, `(?m)^HELPER_NAME=(\S+)$`)
	if want := path.Base(AgentJarPath); jar != want {
		t.Errorf("%s: JAR_NAME=%s, the agent loads %s", script, jar, want)
	}
	if want := path.Base(AttachHelperPath); helper != want {
		t.Errorf("%s: HELPER_NAME=%s, the agent runs %s", script, helper, want)
	}
	if got := value("../../java-agent/build.gradle.kts", `archiveFileName\.set\("([^"]+)"\)`); got != jar {
		t.Errorf("build.gradle.kts builds %s, the script copies %s", got, jar)
	}
	if _, err := os.Stat("../../cmd/" + helper + "/main.go"); err != nil {
		t.Errorf("the script builds ./cmd/%s: %v", helper, err)
	}
}
