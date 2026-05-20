// SPDX-License-Identifier: Apache-2.0

package kubewebhook

import (
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// DefaultJavaImagePattern matches container images that we can be reasonably
// certain run a JVM. Conservative on purpose — false positives mean we
// inject the agent into things that aren't Java, which would at worst waste
// a small amount of memory on the init container. False negatives mean we
// silently miss Java workloads, which is the more important failure to avoid.
//
// Tuned against the most common enterprise Java base images on Docker Hub
// and Quay. The pattern is case-insensitive.
const DefaultJavaImagePattern = `(?i)` +
	`(eclipse-temurin|adoptopenjdk|amazoncorretto|openjdk` +
	`|maven|gradle` +
	`|tomcat|jetty|wildfly|jboss|payara|liberty|liberty-base` +
	`|spring-boot|springboot` +
	`|kafka|zookeeper|cassandra|elasticsearch|logstash` +
	`)`

// IsJavaContainer returns true when the container looks like a JVM workload
// based on its image name, environment variables, or command.
//
// Three signals in priority order:
//
//  1. **Image regex match** (e.g. `eclipse-temurin:17-jre`). Strongest signal
//     because operators choose the image deliberately.
//  2. **`JAVA_HOME` or `JAVA_TOOL_OPTIONS` env var present.** Strong signal
//     because Java apps and base images set these.
//  3. **`command` or `args` mentions `java`.** Weakest signal; only used when
//     the image is opaque (e.g. distroless or scratch-based).
//
// Returns the matched signal as a string for diagnostic logging.
func IsJavaContainer(c *corev1.Container, imageRe *regexp.Regexp) (bool, string) {
	if c == nil {
		return false, ""
	}
	if imageRe != nil && imageRe.MatchString(c.Image) {
		return true, "image-match"
	}
	for _, env := range c.Env {
		if env.Name == "JAVA_HOME" || env.Name == "JAVA_TOOL_OPTIONS" {
			return true, "env-" + env.Name
		}
	}
	if commandMentionsJava(c.Command) || commandMentionsJava(c.Args) {
		return true, "cmd-java"
	}
	return false, ""
}

// IsJavaPod returns the list of container indices in `pod.Spec.Containers`
// that look Java. Empty slice means no Java containers — the webhook will
// NOT mutate the pod in that case.
//
// Note we deliberately ignore init containers and ephemeral containers:
// the agent attaches to app containers, not setup/debug helpers.
func IsJavaPod(pod *corev1.Pod, imageRe *regexp.Regexp) []int {
	if pod == nil {
		return nil
	}
	var idx []int
	for i := range pod.Spec.Containers {
		if isJava, _ := IsJavaContainer(&pod.Spec.Containers[i], imageRe); isJava {
			idx = append(idx, i)
		}
	}
	return idx
}

func commandMentionsJava(parts []string) bool {
	for _, p := range parts {
		// "java", "/usr/bin/java", "java -jar foo.jar", "exec java ..."
		lower := strings.ToLower(p)
		if lower == "java" ||
			strings.HasSuffix(lower, "/java") ||
			strings.HasPrefix(lower, "java ") ||
			strings.Contains(lower, " java ") ||
			strings.HasSuffix(lower, " java") {
			return true
		}
	}
	return false
}
