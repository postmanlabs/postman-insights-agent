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

	// Create the file
	file, err := os.Create(fileDirectory + fileName)
	if err != nil {
		return errors.Wrapf(err, "Failed to create %s file in %s directory\n", fileName, fileDirectory)
	}

	// Write the data to the file
	err = tmpl.Execute(file, data)
	if err != nil {
		return errors.Wrapf(err, "Failed to write values to %s file\n", fileName)
	}

	// Change file permissions to 600.
	// This is to ensure that the file is only readable and writable by the owner.
	// As it might contain some sensitive information.
	err = os.Chmod(fileDirectory+fileName, 0600)
	if err != nil {
		return errors.Wrapf(err, "Failed to change %s file permissions\n", fileName)
	}
	return nil
}
