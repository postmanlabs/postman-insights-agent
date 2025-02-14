package cri_apis

type LinuxNamespace struct {
	Type string `json:"type"`
	Path string `json:"path"`
}

type LinuxProcess struct {
	Env []string `json:"env"`
}

type LinuxRuntimeSpec struct {
	Namespaces []LinuxNamespace `json:"namespaces"`
}

type RuntimeSpec struct {
	Linux   *LinuxRuntimeSpec `json:"linux"`
	Process *LinuxProcess     `json:"process"`
}

type KeyValue struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

type Config struct {
	Envs []*KeyValue `json:"envs"`
}

// Only define required info
type ContainerInfo struct {
	RuntimeSpec RuntimeSpec `json:"runtimeSpec"`
	// Ref from pb.ContainerConfig
	Config Config `json:"config"`
}
