package models

import (
	"database/sql"
	"time"
)

// TargetType represents the type of target
type TargetType string

const (
	TargetTypeDomain    TargetType = "domain"
	TargetTypeSubdomain TargetType = "subdomain"
	TargetTypeURL       TargetType = "url"
	TargetTypeIPPort    TargetType = "ip_port"
	TargetTypeUnknown   TargetType = "unknown"
)

// Target represents a target in a bug bounty program
type Target struct {
	ID           int            `json:"id"`
	ProgramID    int            `json:"program_id"`
	Target       string         `json:"target"`
	Type         TargetType     `json:"type"`
	Source       sql.NullString `json:"source,omitempty"`
	Alive        bool           `json:"alive"`
	LastChecked  sql.NullTime   `json:"last_checked,omitempty"`
	Tested       bool           `json:"tested"`
	TestedDate   sql.NullTime   `json:"tested_date,omitempty"`
	TestNotes    sql.NullString `json:"test_notes,omitempty"`
	Notes        sql.NullString `json:"notes,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
}

// TargetService defines the interface for target operations
type TargetService interface {
	Create(target *Target) error
	GetByID(id int) (*Target, error)
	GetByProgramAndTarget(programID int, target string) (*Target, error)
	Update(target *Target) error
	Delete(id int) error
	ListByProgram(programID int) ([]*Target, error)
	ListAlive() ([]*Target, error)
}

// TargetRepository implements TargetService with database operations
type TargetRepository struct {
	DB *sql.DB
}

// NewTargetRepository creates a new target repository
func NewTargetRepository(db *sql.DB) *TargetRepository {
	return &TargetRepository{DB: db}
}

// Create inserts a new target into the database
func (r *TargetRepository) Create(target *Target) error {
	query := `INSERT INTO targets (program_id, target, type, source, alive, last_checked, 
	          tested, tested_date, test_notes, notes) 
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	
	result, err := r.DB.Exec(query, target.ProgramID, target.Target, target.Type, 
		target.Source, target.Alive, target.LastChecked, target.Tested, 
		target.TestedDate, target.TestNotes, target.Notes)
	if err != nil {
		return err
	}
	
	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	
	target.ID = int(id)
	return nil
}

// GetByID retrieves a target by its ID
func (r *TargetRepository) GetByID(id int) (*Target, error) {
	query := `SELECT id, program_id, target, type, source, alive, last_checked, 
	          tested, tested_date, test_notes, notes, created_at 
	          FROM targets WHERE id = ?`
	
	target := &Target{}
	err := r.DB.QueryRow(query, id).Scan(
		&target.ID, &target.ProgramID, &target.Target, &target.Type, &target.Source,
		&target.Alive, &target.LastChecked, &target.Tested, &target.TestedDate,
		&target.TestNotes, &target.Notes, &target.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	
	return target, nil
}

// GetByProgramAndTarget retrieves a target by program ID and target value
func (r *TargetRepository) GetByProgramAndTarget(programID int, target string) (*Target, error) {
	query := `SELECT id, program_id, target, type, source, alive, last_checked, 
	          tested, tested_date, test_notes, notes, created_at 
	          FROM targets WHERE program_id = ? AND target = ?`
	
	targetObj := &Target{}
	err := r.DB.QueryRow(query, programID, target).Scan(
		&targetObj.ID, &targetObj.ProgramID, &targetObj.Target, &targetObj.Type, &targetObj.Source,
		&targetObj.Alive, &targetObj.LastChecked, &targetObj.Tested, &targetObj.TestedDate,
		&targetObj.TestNotes, &targetObj.Notes, &targetObj.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	
	return targetObj, nil
}

// Update modifies an existing target
func (r *TargetRepository) Update(target *Target) error {
	query := `UPDATE targets SET program_id = ?, target = ?, type = ?, source = ?, 
	          alive = ?, last_checked = ?, tested = ?, tested_date = ?, 
	          test_notes = ?, notes = ? WHERE id = ?`
	
	_, err := r.DB.Exec(query, target.ProgramID, target.Target, target.Type, 
		target.Source, target.Alive, target.LastChecked, target.Tested, 
		target.TestedDate, target.TestNotes, target.Notes, target.ID)
	
	return err
}

// Delete removes a target from the database
func (r *TargetRepository) Delete(id int) error {
	query := "DELETE FROM targets WHERE id = ?"
	_, err := r.DB.Exec(query, id)
	return err
}

// ListByProgram retrieves all targets for a specific program
func (r *TargetRepository) ListByProgram(programID int) ([]*Target, error) {
	query := `SELECT id, program_id, target, type, source, alive, last_checked, 
	          tested, tested_date, test_notes, notes, created_at 
	          FROM targets WHERE program_id = ? ORDER BY target`
	
	rows, err := r.DB.Query(query, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var targets []*Target
	for rows.Next() {
		target := &Target{}
		err := rows.Scan(
			&target.ID, &target.ProgramID, &target.Target, &target.Type, &target.Source,
			&target.Alive, &target.LastChecked, &target.Tested, &target.TestedDate,
			&target.TestNotes, &target.Notes, &target.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	
	return targets, nil
}

// ListAlive retrieves all alive targets
func (r *TargetRepository) ListAlive() ([]*Target, error) {
	query := `SELECT id, program_id, target, type, source, alive, last_checked, 
	          tested, tested_date, test_notes, notes, created_at 
	          FROM targets WHERE alive = 1 ORDER BY target`
	
	rows, err := r.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var targets []*Target
	for rows.Next() {
		target := &Target{}
		err := rows.Scan(
			&target.ID, &target.ProgramID, &target.Target, &target.Type, &target.Source,
			&target.Alive, &target.LastChecked, &target.Tested, &target.TestedDate,
			&target.TestNotes, &target.Notes, &target.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	
	return targets, nil
}
