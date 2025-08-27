package processors

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// GetOrCreateTarget checks if a target exists and creates it if not
func GetOrCreateTarget(db *sql.DB, targetURL, toolName string, programID int) (int, error) {
	// Determine target type
	targetType := "url"
	switch {
	case strings.Count(targetURL, ".") == 1 && !strings.Contains(targetURL, "/") && !strings.Contains(targetURL, ":"):
		targetType = "domain"
	case strings.Count(targetURL, ".") > 1 && !strings.Contains(targetURL, "/") && !strings.Contains(targetURL, ":"):
		targetType = "subdomain"
	case strings.Contains(targetURL, "://"):
		targetType = "url"
	case strings.Contains(targetURL, ":"):
		targetType = "ip_port"
	default:
		targetType = "unknown"
	}

	// Check if target already exists
	var targetID int
	err := db.QueryRow(
		"SELECT id FROM targets WHERE target = ? AND program_id = ?",
		targetURL, programID,
	).Scan(&targetID)

	if err == sql.ErrNoRows {
		// Target doesn't exist, create it
		result, err := db.Exec(
			"INSERT INTO targets (program_id, target, type, source, last_checked) VALUES (?, ?, ?, ?, ?)",
			programID, targetURL, targetType, toolName, time.Now(),
		)
		if err != nil {
			return 0, fmt.Errorf("failed to create target: %v", err)
		}

		id, err := result.LastInsertId()
		if err != nil {
			return 0, fmt.Errorf("failed to get target ID: %v", err)
		}
		return int(id), nil
	} else if err != nil {
		return 0, fmt.Errorf("failed to query target: %v", err)
	}

	return targetID, nil
}
