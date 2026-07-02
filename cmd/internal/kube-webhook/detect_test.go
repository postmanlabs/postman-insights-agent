package kubewebhook

import (
	"regexp"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestIsJavaContainer(t *testing.T) {
	re := regexp.MustCompile(DefaultJavaImagePattern)

	cases := []struct {
		name     string
		image    string
		env      []corev1.EnvVar
		cmd      []string
		args     []string
		wantJava bool
		wantWhy  string
	}{
		// --- image-match positive cases ---
		{"temurin-17",     "eclipse-temurin:17-jre",                 nil, nil, nil, true, "image-match"},
		{"corretto",       "amazoncorretto:17",                       nil, nil, nil, true, "image-match"},
		{"openjdk-21",     "openjdk:21-jdk-slim",                     nil, nil, nil, true, "image-match"},
		{"tomcat",         "tomcat:10.1",                             nil, nil, nil, true, "image-match"},
		{"jetty",          "jetty:12",                                nil, nil, nil, true, "image-match"},
		{"wildfly",        "wildfly:33",                              nil, nil, nil, true, "image-match"},
		{"spring-boot",    "registry.example.com/spring-boot:1.2.3",  nil, nil, nil, true, "image-match"},
		{"kafka",          "confluentinc/cp-kafka:7.5.0",             nil, nil, nil, true, "image-match"},

		// --- env-var positive cases ---
		{"opaque-image-with-JAVA_HOME", "scratch",  []corev1.EnvVar{{Name: "JAVA_HOME", Value: "/opt/jdk"}}, nil, nil, true, "env-JAVA_HOME"},
		{"opaque-with-JAVA_TOOL_OPTIONS","scratch", []corev1.EnvVar{{Name: "JAVA_TOOL_OPTIONS", Value: "-Xmx2g"}}, nil, nil, true, "env-JAVA_TOOL_OPTIONS"},

		// --- command-mentions-java positive cases ---
		{"cmd-java-bare",  "alpine",  nil, []string{"java"}, nil, true, "cmd-java"},
		{"cmd-java-path",  "alpine",  nil, []string{"/usr/lib/jvm/java-17-openjdk/bin/java"}, nil, true, "cmd-java"},
		{"args-java",      "alpine",  nil, nil, []string{"sh", "-c", "java -jar /app.jar"}, true, "cmd-java"},

		// --- negative cases ---
		{"node-image",     "node:20-alpine",        nil, nil, nil, false, ""},
		{"python",         "python:3.12",           nil, nil, nil, false, ""},
		{"nginx",          "nginx:1.27",            nil, nil, nil, false, ""},
		{"go-app",         "alpine:3",              nil, []string{"/usr/local/bin/myapp"}, nil, false, ""},
		{"scratch-bare",   "scratch",               nil, nil, nil, false, ""},
		{"non-java-env",   "alpine",                []corev1.EnvVar{{Name: "FOO", Value: "bar"}}, nil, nil, false, ""},
		// Case insensitivity should NOT cause "javascript" image to match.
		// "node" doesn't contain the regex's tokens; this is a sanity check.
		{"javascript-not-matched", "node:javascript-build", nil, nil, nil, false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &corev1.Container{
				Image:   tc.image,
				Env:     tc.env,
				Command: tc.cmd,
				Args:    tc.args,
			}
			gotJava, gotWhy := IsJavaContainer(c, re)
			if gotJava != tc.wantJava {
				t.Fatalf("IsJavaContainer(%s) = %v, want %v (matched=%q)", tc.name, gotJava, tc.wantJava, gotWhy)
			}
			if gotJava && gotWhy != tc.wantWhy {
				t.Fatalf("IsJavaContainer(%s) why=%q, want %q", tc.name, gotWhy, tc.wantWhy)
			}
		})
	}
}

func TestIsJavaPod(t *testing.T) {
	re := regexp.MustCompile(DefaultJavaImagePattern)

	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "sidecar", Image: "nginx:1.27"},
				{Name: "app",     Image: "eclipse-temurin:17-jre"},
				{Name: "another", Image: "tomcat:10"},
			},
		},
	}
	idx := IsJavaPod(pod, re)
	if len(idx) != 2 || idx[0] != 1 || idx[1] != 2 {
		t.Fatalf("expected Java containers at [1,2], got %v", idx)
	}

	// All-non-Java pod returns empty
	pod2 := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "nginx", Image: "nginx:1.27"},
			},
		},
	}
	if got := IsJavaPod(pod2, re); len(got) != 0 {
		t.Fatalf("expected no Java containers, got %v", got)
	}

	// Nil-safe
	if got := IsJavaPod(nil, re); got != nil {
		t.Fatalf("nil pod should return nil, got %v", got)
	}
}
