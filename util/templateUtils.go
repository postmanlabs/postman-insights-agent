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
	return nil
}
