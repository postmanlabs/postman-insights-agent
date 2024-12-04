package ec2

import (
	"embed"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/cfg"
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/apidump"
	"github.com/postmanlabs/postman-insights-agent/consts"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
	"github.com/postmanlabs/postman-insights-agent/util"
)

const (
	envFileName         = "postman-insights-agent"
	envFileTemplateName = "postman-insights-agent.env.tmpl"
	envFileBasePath     = "/etc/default/"
	envFilePath         = envFileBasePath + envFileName

	serviceFileName         = "postman-insights-agent.service"
	serviceFileTemplateName = "postman-insights-agent.service.tmpl"
	serviceFileBasePath     = "/usr/lib/systemd/system/"
	serviceFilePath         = serviceFileBasePath + serviceFileName

	// Output of command: systemctl is-enabled postman-insights-agent
	// Refer: https://www.freedesktop.org/software/systemd/man/latest/systemctl.html#Exit%20status
	enabled     = "enabled"                                                                                     // exit code: 0
	disabled    = "disabled"                                                                                    // exit code: 1
	nonExisting = "Failed to get unit file state for postman-insights-agent.service: No such file or directory" // exit code: 1
)

var (
	agentInstallPaths = [...]string{
		// Agent executable name
		"postman-insights-agent",

		// If agent is not found in directories named by PATH environment variable then look for below predefined paths

		// Debian install path
		"/usr/bin/postman-insights-agent",
		// Homebrew install path
		"/opt/homebrew/bin/postman-insights-agent",
		// Usr local install path
		"/usr/local/bin/postman-insights-agent",
	}

	// Embed files inside the binary. Requires Go >=1.16
	// FS is used for easier template parsing

	//go:embed postman-insights-agent.env.tmpl
	envFileFS embed.FS

	//go:embed postman-insights-agent.service.tmpl
	serviceFileFS embed.FS
)

// Helper function for reporting telemetry
func reportStep(stepName string) {
	telemetry.WorkflowStep("Starting systemd configuration", stepName)
}

func setupAgentForServer(projectID string) error {

	err := checkUserPermissions()
	if err != nil {
		return err
	}
	err = checkSystemdExists()
	if err != nil {
		return err
	}

	err = configureSystemdFiles(projectID)
	if err != nil {
		return err
	}

	err = enablePostmanInsightsAgent()
	if err != nil {
		return err
	}

	return nil
}

func askToReconfigure() error {
	var isReconfigure bool

	printer.Infof("postman-insights-agent is already present as a systemd service\n")
	printer.Infof("Helpful commands\n"+
		"Check status: systemctl status postman-insights-agent\n"+
		"Disable agent: systemctl disable --now postman-insights-agent\n"+
		"Check Logs: journalctl -fu postman-insights-agent\n"+
		"Check env file: cat %s\n"+
		"Check systemd service file: cat %s\n",
		envFilePath, serviceFilePath)

	err := survey.AskOne(
		&survey.Confirm{
			Message: "Overwrite old API key and Project ID values in systemd configuration file with current values?",
			Default: true,
			Help:    "Any edits made to systemd configuration files will be over-written.",
		},
		&isReconfigure,
	)
	if !isReconfigure {
		printer.Infof("Exiting setup \n")
		os.Exit(0)
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "failed to run reconfiguration prompt")
	}
	return nil
}

// Check is systemd service already exists
func checkReconfiguration() error {

	cmd := exec.Command("systemctl", []string{"is-enabled", "postman-insights-agent"}...)
	out, err := cmd.CombinedOutput()

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode := exitError.ExitCode()
			if exitCode != 1 {
				return errors.Wrapf(err, "Received non 1 exitcode for systemctl is-enabled. \n Command output:%s \n Please send this log message to %s for assistance\n", out, consts.SupportEmail)
			}
			if strings.Contains(string(out), disabled) {
				return askToReconfigure()
			} else if strings.Contains(string(out), nonExisting) {
				return nil
			}
		}
		return errors.Wrapf(err, "failed to run systemctl is-enabled postman-insights-agent")
	}
	if strings.Contains(string(out), enabled) {
		return askToReconfigure()
	}
	return errors.Errorf("The systemctl is-enabled command produced output the agent doesn't recognize: %q.\nPlease send this log message to %s for assistance\n", string(out), consts.SupportEmail)

}

func checkUserPermissions() error {

	// Exact permissions required are
	// read/write permissions on /etc/default/postman-insights-agent
	// read/write permission on /usr/lib/system/systemd
	// enable, daemon-reload, start, stop permission for systemctl

	printer.Infof("Checking user permissions \n")
	cu, err := user.Current()
	if err != nil {
		return errors.Wrapf(err, "could not get current user")
	}
	if !strings.EqualFold(cu.Name, "root") {
		printer.Errorf("root user is required to setup systemd service and edit related files.\n")
		return errors.Errorf("Please run the command again with root user")
	}
	return nil
}

func checkSystemdExists() error {
	message := "Checking if systemd exists"
	printer.Infof(message + "\n")
	reportStep(message)

	_, serr := exec.LookPath("systemctl")
	if serr != nil {
		printer.Errorf("We don't have support for non-systemd OS as of now.\n For more information please contact %s.\n", consts.SupportEmail)
		return errors.Errorf("Could not find systemd binary in your OS.")
	}
	return nil
}

func getAgentInstallPath() (string, error) {
	message := "Checking agent install path "
	printer.Infof(message + "\n")
	reportStep(message)

	for _, possiblePath := range agentInstallPaths {
		if path, err := exec.LookPath(possiblePath); err == nil {
			return path, nil
		}
	}

	return "", errors.Errorf("Could not find postman-insights-agent binary in your OS.")
}

func configureSystemdFiles(projectID string) error {
	message := "Configuring systemd files"
	printer.Infof(message + "\n")
	reportStep(message)

	err := checkReconfiguration()
	if err != nil {
		return err
	}

	// -------- Write env file --------
	apiKey, env := cfg.GetPostmanAPIKeyAndEnvironment()
	envFiledata := struct {
		PostmanEnv    string
		PostmanAPIKey string
		ProjectID     string
	}{
		PostmanAPIKey: apiKey,
		ProjectID:     projectID,
	}
	if env != "" {
		envFiledata.PostmanEnv = env
	}

	// Generate and write the env file, with permissions 0600 (read/write for owner only)
	err = util.GenerateAndWriteTemplateFile(envFileFS, envFileTemplateName, envFileBasePath, envFileName, 0600, envFiledata)
	if err != nil {
		return err
	}

	// -------- Write service file --------
	agentInstallPath, err := getAgentInstallPath()
	if err != nil {
		return err
	}

	// Get the common apidump args
	apidumpArgs := apidump.ConvertCommonApiDumpFlagsToArgs(apidumpFlags)

	// Join the extra apidump args to a single string
	apidumpArgsStr := strings.Join(apidumpArgs, " ")

	serviceFileData := struct {
		AgentInstallPath string
		ExtraApidumpArgs string
	}{
		AgentInstallPath: agentInstallPath,
		ExtraApidumpArgs: apidumpArgsStr,
	}

	// Generate and write the service file, with permissions 0600 (read/write for owner only)
	err = util.GenerateAndWriteTemplateFile(serviceFileFS, serviceFileTemplateName, serviceFileBasePath, serviceFileName, 0600, serviceFileData)
	if err != nil {
		return err
	}

	return nil
}

// Starts the Postman Insights Agent as a systemd service
func enablePostmanInsightsAgent() error {
	message := "Enabling postman-insights-agent as a service"
	reportStep(message)
	printer.Infof(message + "\n")

	cmd := exec.Command("systemctl", []string{"daemon-reload"}...)
	_, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "failed to run systemctl daemon-reload")
	}
	// systemctl start postman-insights-agent.service
	cmd = exec.Command("systemctl", []string{"enable", "--now", serviceFileName}...)
	_, err = cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "failed to run systemctl enable --now")
	}
	printer.Infof("Postman Insights Agent enabled as a systemd service. Please check logs using the below command \n")
	printer.Infof("journalctl -fu postman-insights-agent \n")

	return nil
}
