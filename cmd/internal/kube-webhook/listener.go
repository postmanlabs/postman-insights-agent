package kubewebhook

import "net"

// bindListener resolves the address (handling :0 for OS-assigned ports)
// and returns a bound TCP listener. Split out so Start() can use it for
// both plaintext and TLS paths.
func bindListener(addr string) (net.Listener, error) {
	if addr == "" {
		addr = ":8443"
	}
	return net.Listen("tcp", addr)
}
