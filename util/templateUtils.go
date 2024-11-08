package util

import (
	"embed"
	"os"
	"os/exec"
	"text/template"

	"github.com/pkg/errors"
)

func GenerateAndWriteTemplateFile(
	fileFS embed.FS,
	templateName string,
	fileDirectory string,
	fileName string,
	filePermissions os.FileMode,
	data interface{},
) error {
	// Parse the template file
	tmpl, err := template.ParseFS(fileFS, templateName)
	if err != nil {
		return errors.Wrapf(err, "Failed to parse %s file\n", fileName)
	}

	// Ensure directory exists
	cmd := exec.Command("mkdir", []string{"-p", fileDirectory}...)
	_, err = cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "Failed to create %s directory\n", fileDirectory)
	}

	// Create the file with the given permissions
	file, err := os.OpenFile(fileDirectory+fileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, filePermissions)
	if err != nil {
		return errors.Wrapf(err, "Failed to create %s file in %s directory with permissions %d\n", fileName, fileDirectory, filePermissions)
	}
	defer file.Close()

	// Write the data to the file
	err = tmpl.Execute(file, data)
	if err != nil {
		return errors.Wrapf(err, "Failed to write values to %s file\n", fileName)
	}

	return nil
}
