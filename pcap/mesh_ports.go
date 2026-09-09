package pcap

// Istio / Envoy sidecar listen and data-plane ports commonly used in-pod.
// Kept as one shared definition for:
//   - apidump listen-port discovery (exclude from auto inbound BPF)
//   - pcap Direction tie-break (both-local → outbound when dest is mesh proxy)
//
// Extend carefully when adding other meshes (Linkerd, etc.); ranges are
// best-effort and config-dependent.
const (
	istioEnvoyPortMin uint16 = 15000
	istioEnvoyPortMax uint16 = 15090
)

// IsMeshProxyPort reports whether port is a known sidecar / mesh proxy port
// that should not be treated as an application listen port.
func IsMeshProxyPort(port uint16) bool {
	return port >= istioEnvoyPortMin && port <= istioEnvoyPortMax
}
