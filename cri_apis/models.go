package cri_apis

import (
	pb "k8s.io/cri-api/pkg/apis/runtime/v1"
)

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

type ContainerResponse struct {
	Status *pb.ContainerStatus `json:"status,omitempty"`
	Info   *ContainerInfo      `json:"info,omitempty"`
}
