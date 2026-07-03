package kubewebhook

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"syscall"

	"github.com/spf13/cobra"
)

var (
	flagAddr      string
	flagCertFile  string
	flagKeyFile   string
	flagInitImage string
	flagImageRe   string
)

func init() {
	Cmd.Flags().StringVar(&flagAddr,      "addr",       ":8443", "Listen address (host:port). Use :0 for an OS-assigned port (tests only).")
	Cmd.Flags().StringVar(&flagCertFile,  "tls-cert",   "",      "Path to the TLS certificate file (PEM). Required in production.")
	Cmd.Flags().StringVar(&flagKeyFile,   "tls-key",    "",      "Path to the TLS private key file (PEM). Required in production.")
	Cmd.Flags().StringVar(&flagInitImage, "init-image", "",
		"Container image containing /opt/postman-java-agent.jar that the init container will copy into the shared volume. Required.")
	Cmd.Flags().StringVar(&flagImageRe,   "java-image-regex", DefaultJavaImagePattern,
		"Regex matching container images that should be treated as Java workloads. Empty disables image-based detection (env/command heuristics still apply).")
}

func runE(cmd *cobra.Command, _ []string) error {
	if flagInitImage == "" {
		return fmt.Errorf("--init-image is required: set it to the postman-insights-agent image (e.g. ghcr.io/postmanlabs/postman-insights-agent:<tag>)")
	}

	var imgRe *regexp.Regexp
	if flagImageRe != "" {
		re, err := regexp.Compile(flagImageRe)
		if err != nil {
			return fmt.Errorf("--java-image-regex: %w", err)
		}
		imgRe = re
	}

	mutator := &Mutator{
		JavaImageRegex: imgRe,
		PatchConfig: MutationConfig{
			InitImage:           flagInitImage,
			InitImagePullPolicy: DefaultMutationConfig().InitImagePullPolicy,
		},
	}

	srv := &Server{
		Addr:     flagAddr,
		CertFile: flagCertFile,
		KeyFile:  flagKeyFile,
		Mutator:  mutator,
	}

	ctx, cancel := signalContext(cmd.Context())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("start webhook server: %w", err)
	}

	scheme := "https"
	if flagCertFile == "" || flagKeyFile == "" {
		scheme = "http"
		fmt.Fprintln(os.Stderr,
			"[postman-insights] WARNING: serving plain HTTP. K8s API server requires HTTPS — "+
				"set --tls-cert and --tls-key for production.")
	}
	fmt.Fprintf(os.Stderr, "[postman-insights] kube-webhook listening on %s://%s\n", scheme, srv.ActualAddr)
	fmt.Fprintln(os.Stderr, "[postman-insights] endpoints: POST /mutate, GET /healthz")

	<-ctx.Done()
	fmt.Fprintln(os.Stderr, "[postman-insights] shutting down (SIGTERM/SIGINT received)…")
	return srv.Stop(context.Background())
}

// signalContext returns a context that is cancelled on SIGINT/SIGTERM.
func signalContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-ctx.Done():
		}
		signal.Stop(sigCh)
	}()
	return ctx, cancel
}
