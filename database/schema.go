package database

import (
	"database/sql"
	"fmt"
	"strings"
)

// InitSchema creates the database tables
func InitSchema(db *sql.DB) error {
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
