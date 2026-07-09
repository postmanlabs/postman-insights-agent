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
	// Pid is the container's init-process PID, expressed in the CRI runtime's
	// own PID namespace (usually the node's PID namespace, which is the
	// agent's view when hostPID:true). Populated by containerd / cri-o in
	// the verbose ContainerStatus response.
	Pid         int         `json:"pid"`
	RuntimeSpec RuntimeSpec `json:"runtimeSpec"`
	// Ref from pb.ContainerConfig
	Config Config `json:"config"`
}
