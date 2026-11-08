package server

import (
	"context"
	"log"
	"strconv"

	"github.com/Autumn-27/artex/db"
)

// A submission wait is derived from current CTF evidence, not the generic pause
// switch. Rejecting/confirming the candidate releases it, while a manual pause
// remains paused. Ordinary task admission and completion are untouched.
func (e *Engine) ctfSubmissionWaiting(ctx context.Context, t *Task) bool {
	if t.Mode != "ctf" || e.m == nil || e.m.pg == nil {
		return false
	}
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return true
	}
	pending, err := e.m.pg.PendingCTFSubmission(ctx, id)
	if err != nil {
		log.Printf("[ctf] task %s submission status: %v", t.ID, err)
		return true
	}
	return pending != nil
}

// Kept separate from generic intent transitions: an unfinished CTF intention
// remains recoverable if the candidate is rejected, rather than being marked done.
func parkCTFSubmissionIntent(store *db.ExplorationStore, intentID int64) error {
	return transitionIntentState(store, intentID, "running", "open")
}
