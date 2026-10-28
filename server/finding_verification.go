package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/Autumn-27/artex/db"
)

// This endpoint queues the existing local-evidence verifier. It grants no
// network/tool authority and never clears or overrides a human decision.
func (s *Server) requestFindingVerification(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "bad finding id")
		return
	}
	var req struct {
		ReviewRequestID string `json:"review_request_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	job, err := pg.RequestFindingReview(r.Context(), id, req.ReviewRequestID)
	switch {
	case errors.Is(err, db.ErrFindingReviewRequestInvalid):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, db.ErrFindingHumanDecisionActive), errors.Is(err, db.ErrTaskArchiveState):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, db.ErrFindingNotFound):
		writeErr(w, http.StatusNotFound, err.Error())
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
	default:
		writeJSON(w, http.StatusAccepted, map[string]any{"job_id": strconv.FormatInt(job, 10), "review_request_id": req.ReviewRequestID})
	}
}
