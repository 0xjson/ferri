package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings" // Add this import

	_ "github.com/mattn/go-sqlite3"
)

// DB is the global database connection
var DB *sql.DB

// Default database path
const DefaultDBPath = "~/bugbounty/db/bounty.db"

// EnsureDBExists creates the database file and schema if it doesn't exist
func EnsureDBExists(dbPath string) error {
	dbPath = expandPath(dbPath)
	
	// Create directory if it doesn't exist
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	// Check if database already exists
	if _, err := os.Stat(dbPath); err == nil {
		return nil // Database already exists
	}

	fmt.Printf("📁 Database not found, creating: %s\n", dbPath)
	
	// Create an empty file
	file, err := os.Create(dbPath)
	if err != nil {
		return fmt.Errorf("failed to create database file: %v", err)
	}
	file.Close()

	// Open database
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}
	defer db.Close()

	// Test connection
	if err := db.Ping(); err != nil {
		return fmt.Errorf("database ping failed: %v", err)
	}

	// Initialize schema
	fmt.Printf("📊 Initializing database schema...\n")
	if err := InitSchema(db); err != nil {
		return fmt.Errorf("failed to initialize schema: %v", err)
	}
	fmt.Printf("✅ Database created and schema initialized successfully\n")

	return nil
}

// InitDB initializes the database connection
func InitDB(dbPath string) (*sql.DB, error) {
	dbPath = expandPath(dbPath)
	
	var err error
	DB, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Test connection
	if err := DB.Ping(); err != nil {
		return nil, fmt.Errorf("database ping failed: %v", err)
	}

	return DB, nil
}

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
