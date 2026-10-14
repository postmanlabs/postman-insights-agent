package kube

import (
	"strings"
	"testing"

	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Java capture is in preview: off unless --https-libraries names it.
func TestRunHTTPSLibrariesDefault(t *testing.T) {
	f := runCmd.PersistentFlags().Lookup("https-libraries")
	require.NotNil(t, f)
	assert.Equal(t, "[openssl]", f.DefValue)
}

func TestOnboardHTTPSLibrariesArg(t *testing.T) {
	defer func(enable bool, libs []string) {
		onboardEnableHTTPSCapture, onboardHTTPSLibraries = enable, libs
	}(onboardEnableHTTPSCapture, onboardHTTPSLibraries)

	for _, tc := range []struct {
		args    []string
		want    string
		wantErr string
	}{
		{args: []string{"--enable-https-capture"}, want: ""},
		{args: nil, want: ""},
		{args: []string{"--enable-https-capture", "--https-libraries=openssl"}, want: "openssl"},
		{args: []string{"--enable-https-capture", "--https-libraries=Java,openssl"}, want: "openssl,java"},
		{args: []string{"--https-libraries=openssl"}, wantErr: "requires --enable-https-capture"},
		{args: []string{"--enable-https-capture", "--https-libraries=openssl,gotls"}, wantErr: "unknown gotls"},
		// Given but empty names no library; it does not mean the default.
		{args: []string{"--enable-https-capture", "--https-libraries="}, wantErr: "names no library"},
		{args: []string{"--https-libraries="}, wantErr: "requires --enable-https-capture"},
	} {
		cmd := &cobra.Command{}
		addOnboardingModeFlags(cmd)
		name := strings.Join(tc.args, " ")
		require.NoError(t, cmd.ParseFlags(tc.args), name)
		got, err := onboardHTTPSLibrariesArg(cmd)
		if tc.wantErr != "" {
			assert.ErrorContains(t, err, tc.wantErr, name)
			continue
		}
		assert.NoError(t, err, name)
		assert.Equal(t, tc.want, got, name)
	}
}

// The generated sidecar passes --https-libraries only when one was chosen,
// so a default manifest follows the agent's default.
func TestSidecarHTTPSArgs(t *testing.T) {
	defer func(domain string) { rest.Domain = domain }(rest.Domain)
	rest.Domain = rest.DefaultDomain()

	for _, tc := range []struct {
		opts SidecarOpts
		want []string
	}{
		{SidecarOpts{}, nil},
		{SidecarOpts{HTTPSLibraries: "openssl"}, nil},
		{SidecarOpts{EnableHTTPSCapture: true}, []string{"--enable-https-capture"}},
		{SidecarOpts{EnableHTTPSCapture: true, HTTPSLibraries: "openssl"},
			[]string{"--enable-https-capture", "--https-libraries=openssl"}},
	} {
		tc.opts.ProjectID = "svc_123"
		assert.Equal(t, tc.want, tc.opts.httpsArgs())

		container := createPostmanSidecar(tc.opts)
		assert.Equal(t, append([]string{"apidump", "--project", "svc_123"}, tc.want...), container.Args)

		tf := string(createTerraformContainer(tc.opts).Bytes())
		for _, arg := range tc.want {
			assert.Contains(t, tf, `"`+arg+`"`)
		}
		if tc.opts.HTTPSLibraries != "" && !tc.opts.EnableHTTPSCapture {
			assert.NotContains(t, tf, "--https-libraries")
		}
	}
}
