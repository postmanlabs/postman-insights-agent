package kubewebhook

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
)

// Server is the HTTPS admission webhook server. Cheap to construct, safe
// for concurrent use after Start returns (Mutator is read-only).
type Server struct {
	Addr     string // e.g. ":8443"
	CertFile string
	KeyFile  string
	Mutator  *Mutator

	// Set after Start. Tests use this to know which port we bound to when
	// Addr=":0" requested an OS-assigned port.
	ActualAddr string

	srv *http.Server
}

// Start binds the listener, begins serving in a goroutine, and returns
// nil on the first successful Listen. Tests can call this with Addr=":0"
// to get an OS-assigned port (read back via s.ActualAddr).
//
// If certFile/keyFile are empty, the server serves PLAINTEXT HTTP. That
// mode is for unit tests ONLY — production must use TLS because the K8s
// API server refuses plain HTTP webhooks.
func (s *Server) Start(ctx context.Context) error {
	if s.Mutator == nil {
		return errors.New("Server.Mutator must be set")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", s.handleMutate)
	mux.HandleFunc("/healthz", s.handleHealthz)

	s.srv = &http.Server{
		Addr:              s.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		// TLSConfig will be set per-call when CertFile is set.
	}

	if s.CertFile == "" || s.KeyFile == "" {
		// Plain HTTP — tests only.
		ln, err := bindListener(s.Addr)
		if err != nil {
			return err
		}
		s.ActualAddr = ln.Addr().String()
		go func() {
			_ = s.srv.Serve(ln)
		}()
		return nil
	}

	// TLS path.
	cert, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
	if err != nil {
		return fmt.Errorf("load tls cert: %w", err)
	}
	s.srv.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := bindListener(s.Addr)
	if err != nil {
		return err
	}
	s.ActualAddr = ln.Addr().String()
	tlsLn := tls.NewListener(ln, s.srv.TLSConfig)
	go func() {
		_ = s.srv.Serve(tlsLn)
	}()
	return nil
}

// Stop initiates a graceful shutdown with a 5s deadline.
func (s *Server) Stop(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.srv.Shutdown(c)
}

// --- handlers ---

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

func (s *Server) handleMutate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20)) // 4 MiB cap
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(w, "decode AdmissionReview: "+err.Error(), http.StatusBadRequest)
		return
	}
	if review.Request == nil {
		http.Error(w, "AdmissionReview.Request is nil", http.StatusBadRequest)
		return
	}

	resp := s.Mutator.Handle(review.Request)

	// Build the wire response.
	out := admissionv1.AdmissionReview{
		TypeMeta: review.TypeMeta,
		Response: resp,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(&out); err != nil {
		// We've already started writing; nothing useful to do here.
		_ = err
	}
}
