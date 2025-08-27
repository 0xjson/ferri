package processors

import (
	"database/sql"
	"fmt"
	"time"
)

// AddReconData adds reconnaissance data to the database
func AddReconData(db *sql.DB, targetID int, tool, data, context string) error {
	_, err := db.Exec(
		"INSERT INTO recon_data (target_id, tool, data, context, timestamp) VALUES (?, ?, ?, ?, ?)",
		targetID, tool, data, context, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to insert recon data: %v", err)
	}
	return nil
}
