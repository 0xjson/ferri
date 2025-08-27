package utils

import "os"

// HasStdinData checks if there's data available on stdin
func HasStdinData() bool {
	stat, _ := os.Stdin.Stat()
	return (stat.Mode() & os.ModeCharDevice) == 0
}
