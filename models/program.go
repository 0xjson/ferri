package models

import (
	"database/sql"
	"time"
)

// Program represents a bug bounty program
type Program struct {
	ID           int            `json:"id"`
	Name         string         `json:"name"`
	URL          sql.NullString `json:"url,omitempty"`
	Scope        sql.NullString `json:"scope,omitempty"`
	OutOfScope   sql.NullString `json:"out_of_scope,omitempty"`
	BountyNotes  sql.NullString `json:"bounty_notes,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
}

// ProgramService defines the interface for program operations
type ProgramService interface {
	Create(program *Program) error
	GetByID(id int) (*Program, error)
	GetByName(name string) (*Program, error)
	Update(program *Program) error
	Delete(id int) error
	List() ([]*Program, error)
}

// ProgramRepository implements ProgramService with database operations
type ProgramRepository struct {
	DB *sql.DB
}

// NewProgramRepository creates a new program repository
func NewProgramRepository(db *sql.DB) *ProgramRepository {
	return &ProgramRepository{DB: db}
}

// Create inserts a new program into the database
func (r *ProgramRepository) Create(program *Program) error {
	query := `INSERT INTO programs (name, url, scope, out_of_scope, bounty_notes) 
	          VALUES (?, ?, ?, ?, ?)`
	
	result, err := r.DB.Exec(query, program.Name, program.URL, program.Scope, 
		program.OutOfScope, program.BountyNotes)
	if err != nil {
		return err
	}
	
	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	
	program.ID = int(id)
	return nil
}

// GetByID retrieves a program by its ID
func (r *ProgramRepository) GetByID(id int) (*Program, error) {
	query := `SELECT id, name, url, scope, out_of_scope, bounty_notes, created_at 
	          FROM programs WHERE id = ?`
	
	program := &Program{}
	err := r.DB.QueryRow(query, id).Scan(
		&program.ID, &program.Name, &program.URL, &program.Scope,
		&program.OutOfScope, &program.BountyNotes, &program.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	
	return program, nil
}

// GetByName retrieves a program by its name
func (r *ProgramRepository) GetByName(name string) (*Program, error) {
	query := `SELECT id, name, url, scope, out_of_scope, bounty_notes, created_at 
	          FROM programs WHERE name = ?`
	
	program := &Program{}
	err := r.DB.QueryRow(query, name).Scan(
		&program.ID, &program.Name, &program.URL, &program.Scope,
		&program.OutOfScope, &program.BountyNotes, &program.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	
	return program, nil
}

// Update modifies an existing program
func (r *ProgramRepository) Update(program *Program) error {
	query := `UPDATE programs SET name = ?, url = ?, scope = ?, 
	          out_of_scope = ?, bounty_notes = ? WHERE id = ?`
	
	_, err := r.DB.Exec(query, program.Name, program.URL, program.Scope,
		program.OutOfScope, program.BountyNotes, program.ID)
	
	return err
}

// Delete removes a program from the database
func (r *ProgramRepository) Delete(id int) error {
	query := "DELETE FROM programs WHERE id = ?"
	_, err := r.DB.Exec(query, id)
	return err
}

// List retrieves all programs
func (r *ProgramRepository) List() ([]*Program, error) {
	query := `SELECT id, name, url, scope, out_of_scope, bounty_notes, created_at 
	          FROM programs ORDER BY name`
	
	rows, err := r.DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var programs []*Program
	for rows.Next() {
		program := &Program{}
		err := rows.Scan(
			&program.ID, &program.Name, &program.URL, &program.Scope,
			&program.OutOfScope, &program.BountyNotes, &program.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		programs = append(programs, program)
	}
	
	return programs, nil
}
