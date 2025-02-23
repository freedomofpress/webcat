package main

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"time"

	"domain-verifier/common"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func main() {
	// Initialize the database.
	common.InitDB()

	router := gin.Default()
	router.SetTrustedProxies([]string{})

	// POST /submit : Accept a domain ingestion and return a UID.
	router.POST("/submit", func(c *gin.Context) {
		var req struct {
			Domain string `json:"domain"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Check if there's an existing active submission for the same domain.
		var activeSubmission common.Submission
		err := common.DB.
			Where("domain = ? AND status NOT IN (?, ?)", req.Domain, common.StateCompleted, common.StateFailed).
			First(&activeSubmission).Error
		if err == nil {
			// Found an active submission.
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "A validation attempt for this domain is already in progress. " +
					"Please wait until the previous attempt reaches a final state (success or failure) before submitting again.",
			})
			return
		}
		// If err is not nil, it might be a "record not found" error, which is what we expect.

		// Create a new submission.
		submission := common.Submission{
			ID:     uuid.New().String(),
			Domain: req.Domain,
			Status: common.StateIngested, // initial FSM state
			Logs:   "[]",
		}
		if err := common.DB.Create(&submission).Error; err != nil {
			// Catch and return any database error.
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"uid": submission.ID, "message": "Domain submitted successfully"})
	})

	// GET /status/:uid : Return the current status and log entries for a submission.
	router.GET("/status/:uid", func(c *gin.Context) {
		uid := c.Param("uid")
		var submission common.Submission
		if err := common.DB.First(&submission, "id = ?", uid).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Submission not found"})
			return
		}
		var logs []common.LogEntry
		_ = json.Unmarshal([]byte(submission.Logs), &logs)
		c.JSON(http.StatusOK, gin.H{
			"domain":       submission.Domain,
			"status":       submission.Status,
			"errorMessage": submission.ErrorMessage,
			"logs":         logs,
		})
	})

	// GET /transparency/:hash : Retrieve a transparency record given its hash.
	router.GET("/transparency/:hash", func(c *gin.Context) {
		hash := c.Param("hash")
		var record common.TransparencyRecord
		if err := common.DB.First(&record, "hash = ?", hash).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Transparency record not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"hash":      record.Hash,
			"payload":   record.Payload,
			"signature": record.Signature,
			"proof":     record.Proof,
			"createdAt": record.CreatedAt,
		})
	})

	// POST /confirm/:uid
	// Expects JSON payload: { "code": "the-raw-confirmation-code" }
	router.POST("/confirm/:uid", func(c *gin.Context) {
		uid := c.Param("uid")
		var req struct {
			Code string `json:"code"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}

		// Look up the submission.
		var sub common.Submission
		if err := common.DB.First(&sub, "id = ?", uid).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Submission not found"})
			return
		}

		// Ensure the submission is in the waiting state.
		if sub.Status != common.StateAwaitingConfirmation {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Submission is not awaiting confirmation"})
			return
		}

		// Check if the waiting period has expired.
		if sub.WaitUntil != nil && time.Now().After(*sub.WaitUntil) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Confirmation period has expired"})
			return
		}

		// Compute the hash of the provided code.
		hashedCode := common.ComputeSHA256(req.Code)
		if subtle.ConstantTimeCompare([]byte(hashedCode), []byte(sub.ValidationToken)) != 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid confirmation code"})
			return
		}

		// Update the submission status to confirmed.
		sub.Status = common.StateConfirmed
		common.DB.Save(&sub)
		common.AppendLog(&sub, "Submission confirmed via confirmation link")

		c.JSON(http.StatusOK, gin.H{"message": "Submission confirmed"})
	})

	// Start the REST API server on port 8080.
	router.Run(":8080")
}
