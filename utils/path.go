package utils

import (
	"os"
	"path/filepath"
	"strings"
)

// ExpandPath expands ~ to home directory
func ExpandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path // fallback to original if error
		}
		return filepath.Join(home, path[2:])
	}
	return path
}
