package server

import (
	"context"
	"errors"
	"strconv"

	"github.com/Autumn-27/artex/db"
)

func (m *Manager) DecideCTFAnswer(ctx context.Context, t *Task, candidateID, revision int64, state, notes string, finish bool) (db.CTFCandidate, error) {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	if t == nil || t.Mode != "ctf" {
		return db.CTFCandidate{}, errors.New("CTF 任务不存在")
	}
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return db.CTFCandidate{}, err
	}
	c, err := m.pg.DecideCTFCandidate(ctx, id, candidateID, revision, state, notes, finish)
	if err != nil {
		return c, err
	}
	row, err := m.pg.GetTask(id)
	if err != nil {
		return c, err
	}
	m.mirrorCTFLifecycle(t, row)
	return c, nil
}

func (m *Manager) mirrorCTFLifecycle(t *Task, row *db.Task) {
	t.updateLifecycle(func(s *taskLifecycleState) {
		s.Status, s.Paused, s.Queued = row.Status, row.Paused, row.Queued
		s.QueuedAt = 0
		if row.QueuedAt != nil {
			s.QueuedAt = row.QueuedAt.UnixNano()
		}
		s.QueueMode = row.QueueMode
		s.CompletedAt = 0
		if row.CompletedAt != nil {
			s.CompletedAt = row.CompletedAt.Unix()
		}
	})
}
