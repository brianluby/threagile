package utils

import (
	"strings"
)

// SanitizeID converts a string to a valid Threagile ID by replacing invalid characters
// with underscores and converting to lowercase
func SanitizeID(s string) string {
	result := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, s)
	return strings.ToLower(result)
}