package kube

import (
	"strings"
	"testing"
)

// With HTTPS capture, the injected pod gets hostPID and a volume for each of
// the sidecar's mounts, so the Deployment kube inject writes is valid; and
// the Helm and Terraform fragments name the same volumes.
func TestInjectedSidecarPodSettings(t *testing.T) {
	sidecar := injectedSidecar(SidecarOpts{ProjectID: "svc_test", EnableHTTPSCapture: true})
	if !sidecar.HostPID {
		t.Error("hostPID is not set")
	}
	volumes := map[string]string{}
	for _, v := range sidecar.Volumes {
		if v.HostPath == nil {
			t.Fatalf("volume %s is not a hostPath volume", v.Name)
		}
		volumes[v.Name] = v.HostPath.Path
	}
	mounts := sidecar.Container.VolumeMounts
	if len(mounts) == 0 || len(mounts) != len(volumes) {
		t.Fatalf("%d mounts and %d volumes", len(mounts), len(volumes))
	}
	note := helmPodSpecNote()
	tf := string(createTerraformContainer(SidecarOpts{ProjectID: "svc_test", EnableHTTPSCapture: true}).Bytes())
	for _, m := range mounts {
		path, ok := volumes[m.Name]
		if !ok {
			t.Errorf("mount %s at %s has no volume", m.Name, m.MountPath)
			continue
		}
		if !strings.Contains(note, "name: "+m.Name+"\n#             hostPath: { path: "+path+",") {
			t.Errorf("the Helm note does not name volume %s of %s:\n%s", m.Name, path, note)
		}
		if !strings.Contains(tf, `volume { name = "`+m.Name+`" host_path { path = "`+path+`" } }`) {
			t.Errorf("the Terraform note does not name volume %s of %s:\n%s", m.Name, path, tf)
		}
	}

	plain := injectedSidecar(SidecarOpts{ProjectID: "svc_test"})
	if plain.HostPID || len(plain.Volumes) > 0 || len(plain.Container.VolumeMounts) > 0 {
		t.Errorf("without HTTPS capture the sidecar has hostPID %v, %d volumes and %d mounts",
			plain.HostPID, len(plain.Volumes), len(plain.Container.VolumeMounts))
	}
}
