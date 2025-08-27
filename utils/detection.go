package utils

import (
	"regexp"
)

// Tool patterns for auto-detection
var toolPatterns = map[string]*regexp.Regexp{
	"subfinder":   regexp.MustCompile(`subfinder|subdomains?`),
	"amass":       regexp.MustCompile(`amass`),
	"assetfinder": regexp.MustCompile(`assetfinder`),
	"httpx":       regexp.MustCompile(`httpx|http`),
	"nuclei":      regexp.MustCompile(`nuclei`),
	"waybackurls": regexp.MustCompile(`wayback|archive`),
	"gau":         regexp.MustCompile(`gau`),
	"ffuf":        regexp.MustCompile(`ffuf|fuzz`),
	"gobuster":    regexp.MustCompile(`gobuster|dirbust`),
}

// DetectTool tries to auto-detect the tool from process information
func DetectTool() string {
	// Simple detection based on common patterns
	return "pipeline_auto"
}
