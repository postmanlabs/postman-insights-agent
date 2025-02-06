package kube_apis

import "strings"

// isImageEqual compares two container image names to check if they are equal, ignoring the tag part.
// It splits the image names by the colon (:) and compares the base names case-insensitively.
func isImageEqual(image1 string, image2 string) bool {
	image1 = strings.Split(image1, ":")[0]
	image2 = strings.Split(image2, ":")[0]
	return strings.EqualFold(image1, image2)
}
