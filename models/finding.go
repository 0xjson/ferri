package models

import (
	"database/sql"
	"time"
)

// FindingSeverity represents the severity level of a finding
type FindingSeverity string

const (
	SeverityCritical FindingSeverity = "critical"
	SeverityHigh     FindingSeverity = "high"
	SeverityMedium   FindingSeverity = "medium"
	SeverityLow      FindingSeverity = "low"
	SeverityInfo     FindingSeverity = "info"
)

// FindingStatus represents the status of a finding
type FindingStatus string

const (
	StatusOpen      FindingStatus = "Open"
	StatusInReview  FindingStatus = "In Review"
	StatusTriaged   FindingStatus = "Triaged"
	StatusResolved  FindingStatus = "Resolved"
	StatusDuplicate FindingStatus = "Duplicate"
	StatusWontFix   FindingStatus = "Won't Fix"
)

// Finding represents a security finding/vulnerability
type Finding struct {
	ID              int              `json:"id"`
	TargetID        int              `json:"target_id"`
	Title           string           `json:"title"`
	Type            sql.NullString   `json:"type,omitempty"`
	Severity        FindingSeverity  `json:"severity"`
	Description     sql.NullString   `json:"description,omitempty"`
	ProofOfConcept  sql.NullString   `json:"proof_of_concept,omitempty"`
	Status          FindingStatus    `json:"status"`
	ReportedDate    sql.NullTime     `json:"reported_date,omitempty"`
	ReportID        sql.NullString   `json:"report_id,omitempty"`
	Notes           sql.NullString   `json:"notes,omitempty"`
	CreatedAt       time.Time        `json:"created_at"`
}

// FindingService defines the interface for finding operations
type FindingService interface {
	Create(finding *Finding) error
	GetByID(id int) (*Finding, error)
	GetByTargetID(targetID int) ([]*Finding, error)
	GetBySeverity(severity FindingSeverity) ([]*Finding, error)
	GetByStatus(status FindingStatus) ([]*Finding, error)
	Update(finding *Finding) error
	Delete(id int) error
}

// FindingRepository implements FindingService with database operations
type FindingRepository struct {
	DB *sql.DB
}

// NewFindingRepository creates a new finding repository
func NewFindingRepository(db *sql.DB) *FindingRepository {
	return &FindingRepository{DB: db}
}

// Create inserts a new finding into the database
func (r *FindingRepository) Create(finding *Finding) error {
	query := `INSERT INTO findings (target_id, title, type, severity, description, 
	          proof_of_concept, status, reported_date, report_id, notes) 
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	
	result, err := r.DB.Exec(query, finding.TargetID, finding.Title, finding.Type, 
		finding.Severity, finding.Description, finding.ProofOfConcept, finding.Status,
		finding.ReportedDate, finding.ReportID, finding.Notes)
	if err != nil {
		return err
	}
	
	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	
	finding.ID = int(id)
	return nil
}

// GetByID retrieves a finding by its ID
func (r *FindingRepository) GetByID(id int) (*Finding, error) {
	query := `SELECT id, target_id, title, type, severity, description, 
	          proof_of_concept, status, reported_date, report_id, notes, created_at 
	          FROM findings WHERE id = ?`
	
	finding := &Finding{}
	err := r.DB.QueryRow(query, id).Scan(
		&finding.ID, &finding.TargetID, &finding.Title, &finding.Type, &finding.Severity,
		&finding.Description, &finding.ProofOfConcept, &finding.Status, &finding.ReportedDate,
		&finding.ReportID, &finding.Notes, &finding.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	
	return finding, nil
}

// GetByTargetID retrieves all findings for a specific target
func (r *FindingRepository) GetByTargetID(targetID int) ([]*Finding, error) {
	query := `SELECT id, target_id, title, type, severity, description, 
	          proof_of_concept, status, reported_date, report_id, notes, created_at 
	          FROM findings WHERE target_id = ? ORDER BY severity DESC, created_at DESC`
	
	rows, err := r.DB.Query(query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var findings []*Finding
	for rows.Next() {
		finding := &Finding{}
		err := rows.Scan(
			&finding.ID, &finding.TargetID, &finding.Title, &finding.Type, &finding.Severity,
			&finding.Description, &finding.ProofOfConcept, &finding.Status, &finding.ReportedDate,
			&finding.ReportID, &finding.Notes, &finding.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	
	return findings, nil
}

// GetBySeverity retrieves all findings with a specific severity
func (r *FindingRepository) GetBySeverity(severity FindingSeverity) ([]*Finding, error) {
	query := `SELECT id, target_id, title, type, severity, description, 
	          proof_of_concept, status, reported_date, report_id, notes, created_at 
	          FROM findings WHERE severity = ? ORDER BY created_at DESC`
	
	rows, err := r.DB.Query(query, severity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var findings []*Finding
	for rows.Next() {
		finding := &Finding{}
		err := rows.Scan(
			&finding.ID, &finding.TargetID, &finding.Title, &finding.Type, &finding.Severity,
			&finding.Description, &finding.ProofOfConcept, &finding.Status, &finding.ReportedDate,
			&finding.ReportID, &finding.Notes, &finding.CreatedAt,
		)
		if err != nil {
		}
		findings = append(findings, finding)
	}
	
	return findings, nil
}

// GetByStatus retrieves all findings with a specific status
func (r *FindingRepository) GetByStatus(status FindingStatus) ([]*Finding, error) {
	query := `SELECT id, target_id, title, type, severity, description, 
	          proof_of_concept, status, reported_date, report_id, notes, created_at 
	          FROM findings WHERE status = ? ORDER BY severity DESC, created_at DESC`
	
	rows, err := r.DB.Query(query, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var findings []*Finding
	for rows.Next() {
		finding := &Finding{}
		err := rows.Scan(
			&finding.ID, &finding.TargetID, &finding.Title, &finding.Type, &finding.Severity,
			&finding.Description, &finding.ProofOfConcept, &finding.Status, &finding.ReportedDate,
			&finding.ReportID, &finding.Notes, &finding.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	
	return findings, nil
}

// Update modifies an existing finding
func (r *FindingRepository) Update(finding *Finding) error {
	query := `UPDATE findings SET target_id = ?, title = ?, type = ?, severity = ?, 
	          description = ?, proof_of_concept = ?, status = ?, reported_date = ?, 
	          report_id = ?, notes = ? WHERE id = ?`
	
	_, err := r.DB.Exec(query, finding.TargetID, finding.Title, finding.Type, 
		finding.Severity, finding.Description, finding.ProofOfConcept, finding.Status,
		finding.ReportedDate, finding.ReportID, finding.Notes, finding.ID)
	
	return err
}

// Delete removes a finding from the database
func (r *FindingRepository) Delete(id int) error {
	query := "DELETE FROM findings WHERE id = ?"
	_, err := r.DB.Exec(query, id)
	return err
}
