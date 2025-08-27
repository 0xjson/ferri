package models

import (
	"database/sql"
	"time"
)

// ReconData represents reconnaissance data collected for a target
type ReconData struct {
	ID        int            `json:"id"`
	TargetID  int            `json:"target_id"`
	Tool      string         `json:"tool"`
	Data      string         `json:"data"`
	Context   sql.NullString `json:"context,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
}

// ReconDataService defines the interface for reconnaissance data operations
type ReconDataService interface {
	Create(data *ReconData) error
	GetByID(id int) (*ReconData, error)
	GetByTargetID(targetID int) ([]*ReconData, error)
	GetByTool(tool string) ([]*ReconData, error)
	Delete(id int) error
}

// ReconDataRepository implements ReconDataService with database operations
type ReconDataRepository struct {
	DB *sql.DB
}

// NewReconDataRepository creates a new recon data repository
func NewReconDataRepository(db *sql.DB) *ReconDataRepository {
	return &ReconDataRepository{DB: db}
}

// Create inserts new reconnaissance data into the database
func (r *ReconDataRepository) Create(data *ReconData) error {
	query := `INSERT INTO recon_data (target_id, tool, data, context, timestamp) 
	          VALUES (?, ?, ?, ?, ?)`
	
	result, err := r.DB.Exec(query, data.TargetID, data.Tool, data.Data, 
		data.Context, data.Timestamp)
	if err != nil {
		return err
	}
	
	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	
	data.ID = int(id)
	return nil
}

// GetByID retrieves reconnaissance data by its ID
func (r *ReconDataRepository) GetByID(id int) (*ReconData, error) {
	query := `SELECT id, target_id, tool, data, context, timestamp 
	          FROM recon_data WHERE id = ?`
	
	data := &ReconData{}
	err := r.DB.QueryRow(query, id).Scan(
		&data.ID, &data.TargetID, &data.Tool, &data.Data, 
		&data.Context, &data.Timestamp,
	)
	if err != nil {
		return nil, err
	}
	
	return data, nil
}

// GetByTargetID retrieves all reconnaissance data for a specific target
func (r *ReconDataRepository) GetByTargetID(targetID int) ([]*ReconData, error) {
	query := `SELECT id, target_id, tool, data, context, timestamp 
	          FROM recon_data WHERE target_id = ? ORDER BY timestamp DESC`
	
	rows, err := r.DB.Query(query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var dataList []*ReconData
	for rows.Next() {
		data := &ReconData{}
		err := rows.Scan(
			&data.ID, &data.TargetID, &data.Tool, &data.Data, 
			&data.Context, &data.Timestamp,
		)
		if err != nil {
			return nil, err
		}
		dataList = append(dataList, data)
	}
	
	return dataList, nil
}

// GetByTool retrieves all reconnaissance data collected by a specific tool
func (r *ReconDataRepository) GetByTool(tool string) ([]*ReconData, error) {
	query := `SELECT id, target_id, tool, data, context, timestamp 
	          FROM recon_data WHERE tool = ? ORDER BY timestamp DESC`
	
	rows, err := r.DB.Query(query, tool)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var dataList []*ReconData
	for rows.Next() {
		data := &ReconData{}
		err := rows.Scan(
			&data.ID, &data.TargetID, &data.Tool, &data.Data, 
			&data.Context, &data.Timestamp,
		)
		if err != nil {
			return nil, err
		}
		dataList = append(dataList, data)
	}
	
	return dataList, nil
}

// Delete removes reconnaissance data from the database
func (r *ReconDataRepository) Delete(id int) error {
	query := "DELETE FROM recon_data WHERE id = ?"
	_, err := r.DB.Exec(query, id)
	return err
}
