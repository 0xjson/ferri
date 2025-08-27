package processors

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"
)

// ExtractDomain extracts the organization name from a domain
func ExtractDomain(input string) string {
	// Remove protocol and path
	re := regexp.MustCompile(`(?i)^(https?://)?([^/]+)`)
	matches := re.FindStringSubmatch(input)
	if len(matches) < 3 {
		return input
	}

	domain := matches[2]
	
	// Remove www. prefix and common subdomains
	domain = strings.TrimPrefix(domain, "www.")
	domain = strings.TrimPrefix(domain, "api.")
	domain = strings.TrimPrefix(domain, "app.")
	domain = strings.TrimPrefix(domain, "dev.")
	domain = strings.TrimPrefix(domain, "test.")
	
	// Extract organization name (example.com -> example)
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return parts[0] // Return the first part (organization name)
	}
	
	return domain
}

// GetOrCreateProgram finds or creates a program based on domain
func GetOrCreateProgram(db *sql.DB, domain string) (int, error) {
	orgName := ExtractDomain(domain)
	
	// Try to find existing program
	var programID int
	err := db.QueryRow("SELECT id FROM programs WHERE name = ?", orgName).Scan(&programID)
	
	if err == sql.ErrNoRows {
		// Program doesn't exist, create it
		scope := fmt.Sprintf("*.%s", strings.TrimPrefix(domain, "www."))
		result, err := db.Exec(
			"INSERT INTO programs (name, scope) VALUES (?, ?)",
			orgName, scope,
		)
		if err != nil {
			return 0, fmt.Errorf("failed to create program: %v", err)
		}
		
		id, err := result.LastInsertId()
		if err != nil {
			return 0, fmt.Errorf("failed to get program ID: %v", err)
		}
		
		fmt.Printf("✨ Created new program: %s (ID: %d)\n", orgName, id)
		return int(id), nil
	} else if err != nil {
		return 0, fmt.Errorf("failed to query program: %v", err)
	}
	
	fmt.Printf("🔍 Using existing program: %s (ID: %d)\n", orgName, programID)
	return programID, nil
}
