package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

// Default database path
const defaultDBPath = "~/bugbounty/db/bounty.db"

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

// initDB initializes or creates the database
func initDB(dbPath string) error {
	// Expand path first
	dbPath = expandPath(dbPath)
	
	// Create directory if it doesn't exist
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	// Check if database exists
	dbExists := true
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		dbExists = false
		fmt.Printf("📁 Database not found, creating: %s\n", dbPath)
		// Just create an empty file - SQLite will create the actual database when we open it
		file, err := os.Create(dbPath)
		if err != nil {
			return fmt.Errorf("failed to create database file: %v", err)
		}
		file.Close()
	}

	// Open database
	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return fmt.Errorf("database ping failed: %v", err)
	}

	// Initialize schema if it's a new database
	if !dbExists {
		fmt.Printf("📊 Initializing database schema...\n")
		if err := initSchema(); err != nil {
			return fmt.Errorf("failed to initialize schema: %v", err)
		}
		fmt.Printf("✅ Database schema initialized successfully\n")
	}

	return nil
}

// initSchema creates the database tables
func initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS programs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		url TEXT,
		scope TEXT,
		out_of_scope TEXT,
		bounty_notes TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS targets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		program_id INTEGER NOT NULL,
		target TEXT NOT NULL,
		type TEXT,
		source TEXT,
		alive BOOLEAN DEFAULT 0,
		last_checked DATETIME,
		tested BOOLEAN DEFAULT 0,
		tested_date DATETIME,
		test_notes TEXT,
		notes TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (program_id) REFERENCES programs (id),
		UNIQUE(program_id, target)
	);

	CREATE TABLE IF NOT EXISTS recon_data (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target_id INTEGER NOT NULL,
		tool TEXT NOT NULL,
		data TEXT NOT NULL,
		context TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (target_id) REFERENCES targets (id)
	);

	CREATE TABLE IF NOT EXISTS findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target_id INTEGER NOT NULL,
		title TEXT NOT NULL,
		type TEXT,
		severity TEXT,
		description TEXT,
		proof_of_concept TEXT,
		status TEXT DEFAULT 'Open',
		reported_date DATETIME,
		report_id TEXT,
		notes TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (target_id) REFERENCES targets (id)
	);

	CREATE INDEX IF NOT EXISTS idx_targets_program ON targets(program_id);
	CREATE INDEX IF NOT EXISTS idx_targets_alive ON targets(alive);
	CREATE INDEX IF NOT EXISTS idx_recon_data_target ON recon_data(target_id);
	`

	// Execute each statement separately to avoid transaction issues
	statements := strings.Split(schema, ";")
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("failed to execute statement '%s': %v", stmt, err)
		}
	}
	return nil
}

// detectTool tries to auto-detect the tool from process information
func detectTool() string {
	// Simple detection based on common patterns
	return "pipeline_auto"
}

// extractDomain extracts the organization name from a domain
func extractDomain(input string) string {
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

// getOrCreateProgram finds or creates a program based on domain
func getOrCreateProgram(domain string) (int, error) {
	orgName := extractDomain(domain)
	
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

// getOrCreateTarget checks if a target exists and creates it if not
func getOrCreateTarget(targetURL, toolName string, programID int) (int, error) {
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

// addReconData adds reconnaissance data to the database
func addReconData(targetID int, tool, data, context string) error {
	_, err := db.Exec(
		"INSERT INTO recon_data (target_id, tool, data, context, timestamp) VALUES (?, ?, ?, ?, ?)",
		targetID, tool, data, context, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to insert recon data: %v", err)
	}
	return nil
}

// expandPath expands ~ to home directory
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path // fallback to original if error
		}
		return filepath.Join(home, path[2:])
	}
	return path
}

func main() {
	// Auto-detect everything!
	dbPath := expandPath(defaultDBPath)
	toolName := detectTool()

	fmt.Printf("🛠️  Auto-detected tool: %s\n", toolName)
	fmt.Printf("💾 Database: %s\n", dbPath)

	// Initialize database
	err := initDB(dbPath)
	if err != nil {
		log.Fatalf("❌ Error initializing database: %v\n", err)
	}
	defer db.Close()

	// Read from stdin
	scanner := bufio.NewScanner(os.Stdin)
	var targets []string
	var firstTarget string

	fmt.Printf("📥 Reading from stdin...\n")
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		targets = append(targets, line)
		if firstTarget == "" {
			firstTarget = line
		}
	}

	if len(targets) == 0 {
		fmt.Println("❌ No input provided via stdin")
		os.Exit(1)
	}

	fmt.Printf("📋 Found %d targets to process\n", len(targets))

	// Extract domain from first target for program creation
	domain := firstTarget
	if strings.Contains(firstTarget, "://") {
		// Extract domain from URL
		re := regexp.MustCompile(`(?i)https?://([^/]+)`)
		if matches := re.FindStringSubmatch(firstTarget); len(matches) > 1 {
			domain = matches[1]
		}
	} else if strings.Contains(firstTarget, ".") {
		// Assume it's a domain or subdomain
		domain = firstTarget
	}

	fmt.Printf("🌐 Extracted domain: %s\n", domain)

	// Get or create program
	programID, err := getOrCreateProgram(domain)
	if err != nil {
		log.Fatalf("❌ Error getting/creating program: %v\n", err)
	}

	// Process all targets
	processedCount := 0
	for _, target := range targets {
		targetID, err := getOrCreateTarget(target, toolName, programID)
		if err != nil {
			log.Printf("⚠️ Error with target %s: %v\n", target, err)
			continue
		}

		err = addReconData(targetID, toolName, target, "Discovered via "+toolName)
		if err != nil {
			log.Printf("⚠️ Error adding recon data for %s: %v\n", target, err)
			continue
		}

		processedCount++
		fmt.Printf("✅ %s\n", target)
	}

	fmt.Printf("\n🎉 Completed! Processed %d/%d targets for program ID: %d\n", 
		processedCount, len(targets), programID)
	
	if processedCount > 0 {
		fmt.Printf("💡 Next: Use 'ferro' to analyze your data!\n")
	} else {
		fmt.Printf("❌ No targets were processed successfully\n")
		os.Exit(1)
	}
}
