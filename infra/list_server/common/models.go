package common

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Submission represents a domain ingestion record that tracks its FSM state,
// logs, and additional data (such as the validation token, payload, and signature).
// There are some duplicate data, but I think it's for good for now.
type Submission struct {
	ID                string `gorm:"primaryKey"`
	Domain            string `gorm:"index"`
	Status            string
	Logs              string
	ValidationToken   string
	Payload           string
	Signature         string
	Hash              string
	WaitUntil         *time.Time
	SigstoreSigners   string
	SigstoreThreshold int
	WebcatAction      string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// LogEntry represents an audit log entry.
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
}

// TransparencyRecord stores all the details necessary to reproduce the final hash.
// External verifiers can query for the record given its hash.
type TransparencyRecord struct {
	ID           string `gorm:"primaryKey"`
	SubmissionID string
	Payload      string
	Signature    string
	Hash         string
	LeafHash     string
	Proof        string
	CreatedAt    time.Time
}

// What is used as a stable list reference
type ListEntry struct {
	Domain    string `gorm:"primaryKey"`
	Signers   string
	Threshold int
	Hash      string
	UpdatedAt time.Time
}

var DB *gorm.DB

// InitDB initializes the database connection and performs auto-migration.
func InitDB(dbpath string) {
	var err error
	// For demonstration we use SQLite; in production, replace with your RDS connection string.
	DB, err = gorm.Open(sqlite.Open(fmt.Sprintf("%s/submissions.db", dbpath)), &gorm.Config{})
	if err != nil {
		log.Fatal("failed to connect database: ", err)
	}
	// Auto-migrate all models.
	DB.AutoMigrate(&Submission{}, &TransparencyRecord{}, &ListEntry{})
}

// AppendLog appends a new log message to a submission's Logs field.
func AppendLog(sub *Submission, message string) {
	var logs []LogEntry
	if sub.Logs != "" {
		_ = json.Unmarshal([]byte(sub.Logs), &logs)
	}
	logs = append(logs, LogEntry{Timestamp: time.Now(), Message: message})
	b, err := json.Marshal(logs)
	if err != nil {
		log.Println("error marshaling logs: ", err)
		return
	}
	sub.Logs = string(b)
	DB.Save(sub)
}
