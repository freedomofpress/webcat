package main

import (
	"log"
	"time"

	"domain-verifier/common"
)

func main() {
	common.InitDB()

	var signer = common.EnsureSigsumKeyExists()
	var policy = common.EnsureSigsumPolicyExists()

	log.Println("Starting background processor")
	for {
		var subs []common.Submission
		// Fetch submissions that are not in a final state (not completed, failed, or waiting for an async task).
		common.DB.
			Where("status NOT IN (?)", []string{common.StateCompleted, common.StateFailed, common.StateSigsumSubmitted}).
			Find(&subs)

		for i := range subs {
			// Process each submission asynchronously.
			go common.ProcessSubmissionFSM(&subs[i], signer, policy)
		}
		time.Sleep(5 * time.Second)
	}
}
