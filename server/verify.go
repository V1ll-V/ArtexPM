package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

const (
	verificationLease       = 10 * time.Minute
	verificationTimeout     = 5 * time.Minute
	verificationMaxAttempts = 3
	verificationConcurrency = 2
)

var errVerifierUnavailable = errors.New("验收器未就绪")

type verificationBodyLoader func(context.Context, *db.EvidenceBundle) error

func (s *Server) SetVerifier(v agent.Verifier) {
	if s != nil {
		s.cfgMu.Lock()
		s.verifier = v
		s.cfgMu.Unlock()
	}
}
func (s *Server) currentVerifier() agent.Verifier {
	if s == nil {
		return nil
	}
	s.cfgMu.Lock()
	v, prov := s.verifier, s.llmProv
	s.cfgMu.Unlock()
	if v != nil {
		return v
	}
	if prov != nil {
		return &agent.LLMVerifier{Prov: prov}
	}
	return nil
}
func (s *Server) processVerificationJob(ctx context.Context, job *db.VerificationJob) error {
	if s == nil || s.m == nil {
		return nil
	}
	err := processVerificationJobWith(ctx, s.m.pg, s.currentVerifier(), job, s.evidenceStore().LoadVerificationBodies)
	if err == nil && job != nil {
		var taskID int64
		if job.SubjectKind == db.SubjectFinding {
			_ = s.m.pg.QueryRowContext(ctx, `SELECT COALESCE(task_id,0) FROM findings WHERE id=$1`, job.SubjectID).Scan(&taskID)
		} else {
			_ = s.m.pg.QueryRowContext(ctx, `SELECT t.id FROM tasks t JOIN exploration_nodes n ON n.exploration_id=t.exploration_id WHERE n.id=$1`, job.SubjectID).Scan(&taskID)
		}
		if task, ok := s.m.Task(fmt.Sprint(taskID)); ok {
			task.Notify()
		}
	}
	return err
}

// The real and test paths both freeze, hydrate and persist the exact input before
// invoking the verifier. A fake Provider can exercise the real LLMVerifier.
func processVerificationJobWith(ctx context.Context, pg *db.DB, v agent.Verifier, job *db.VerificationJob, loaders ...verificationBodyLoader) error {
	if pg == nil || job == nil {
		return nil
	}
	if v == nil {
		return errVerifierUnavailable
	}
	b, err := pg.PrepareVerificationInput(ctx, job.ID, job.LeaseGeneration)
	if err != nil {
		if errors.Is(err, db.ErrVerificationLeaseLost) {
			return nil
		}
		if errors.Is(err, db.ErrVerificationInputStale) || errors.Is(err, db.ErrVerificationPolicyMismatch) || errors.Is(err, db.ErrFindingNotFound) || errors.Is(err, db.ErrGoalNotFound) {
			return pg.SupersedeVerificationJob(ctx, job.ID, job.LeaseGeneration, err.Error())
		}
		return err
	}
	if b.SubjectKind != job.SubjectKind || b.SubjectID != job.SubjectID {
		return fmt.Errorf("验收任务主体与持久化输入不一致")
	}
	if b.SubjectKind == db.SubjectFinding && b.HumanDecision != "" && b.HumanDecision != db.HumanDecisionClear {
		return pg.SupersedeVerificationJob(ctx, job.ID, job.LeaseGeneration, "已有生效人工决定")
	}
	if len(loaders) > 0 && loaders[0] != nil {
		if err = loaders[0](ctx, b); err != nil {
			return err
		}
	}
	b, err = pg.RecordVerificationExecutionInput(ctx, job.ID, job.LeaseGeneration, b)
	if err != nil {
		return err
	}
	if llmVerifier, ok := v.(*agent.LLMVerifier); ok {
		local := *llmVerifier
		observe := local.ObserveResponse
		local.ObserveResponse = func(ctx context.Context, raw string) error {
			if err := pg.RecordVerificationOutput(ctx, job.ID, job.LeaseGeneration, raw); err != nil {
				return err
			}
			if observe != nil {
				return observe(ctx, raw)
			}
			return nil
		}
		v = &local
	}
	result, err := v.Verify(ctx, b)
	if err != nil {
		return err
	}
	if result.PolicyVersion == "" {
		result.PolicyVersion = b.PolicyVersion
	}
	if result.PolicyVersion != b.PolicyVersion {
		return fmt.Errorf("验收器结果策略与冻结输入不一致")
	}
	if result.Decision == db.VerdictSupported && !db.VerificationMaterialComplete(b) {
		return fmt.Errorf("缺少已校验的必要正文，不能确认验收通过")
	}
	var conflict string
	switch b.SubjectKind {
	case db.SubjectFinding:
		conflict, err = db.CommitFindingVerdict(ctx, pg, db.CommitFindingVerdictInput{FindingID: b.SubjectID, JobID: job.ID,
			LeaseGeneration: job.LeaseGeneration, ExpectedInputRevision: b.InputRevision, ExpectedVerdictRevision: b.VerdictRevision,
			ExpectedHumanRevision: b.HumanRevision, PolicyVersion: b.PolicyVersion, Result: result})
	case db.SubjectGoal:
		var expID int64
		if err = pg.QueryRowContext(ctx, `SELECT exploration_id FROM exploration_nodes WHERE id=$1 AND kind='goal'`, b.SubjectID).Scan(&expID); err != nil {
			return err
		}
		verdict := result.GoalVerdict
		if verdict == "" { // injected verifier implementations keep the shared interface
			switch result.Decision {
			case db.VerdictSupported:
				verdict = "met"
			case db.VerdictRefuted:
				verdict = "not_met"
			case db.VerdictNeedsReview:
				verdict = "inconclusive"
			default:
				return fmt.Errorf("未知目标验收判定")
			}
		}
		conflict, err = pg.Exploration(expID).CommitGoalEvaluation(ctx, job.ID, job.LeaseGeneration, verdict, result)
	default:
		return fmt.Errorf("未知验收主体")
	}
	if err != nil {
		return err
	}
	if conflict == db.CommitLeaseLost {
		return nil
	}
	if conflict != db.CommitOK {
		return pg.SupersedeVerificationJob(ctx, job.ID, job.LeaseGeneration, "提交被拒: "+conflict)
	}
	log.Printf("[verifier] %s %d 判定已提交 (job %d, input %s)", b.SubjectKind, b.SubjectID, job.ID, b.InputHash)
	return nil
}

// Slots cover the entire execution, not just one scheduling tick. Cancellation
// and execution timeout are independent of the longer DB lease.
func (sc *Scheduler) runVerificationQueue() {
	if sc == nil || sc.pg == nil || sc.s == nil || sc.s.currentVerifier() == nil {
		return
	}
	parent := sc.verificationCtx
	if parent == nil {
		parent = sc.s.ctx
	}
	if parent == nil {
		parent = context.Background()
	}
	if parent.Err() != nil {
		return
	}
	if sc.verifySlots == nil {
		sc.verifySlots = make(chan struct{}, verificationConcurrency)
	}
	if _, err := sc.pg.ReleaseExpiredVerificationLeases(parent, verificationMaxAttempts); err != nil {
		log.Printf("[verifier] 回收租约失败: %v", err)
		return
	}
	for {
		select {
		case sc.verifySlots <- struct{}{}:
		default:
			return
		}
		job, err := sc.pg.ClaimVerificationJob(parent, verificationLease)
		if err != nil || job == nil {
			<-sc.verifySlots
			if err != nil {
				log.Printf("[verifier] 领取失败: %v", err)
			}
			return
		}
		sc.verifyWG.Add(1)
		go func(j *db.VerificationJob) {
			defer sc.verifyWG.Done()
			defer func() { <-sc.verifySlots }()
			ctx, cancel := context.WithTimeout(parent, verificationTimeout)
			defer cancel()
			if err := sc.s.processVerificationJob(ctx, j); err != nil {
				// Cancellation must still leave a persisted retry/failure state.
				cleanup, stop := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
				defer stop()
				if ferr := sc.pg.FailVerificationJob(cleanup, j.ID, j.LeaseGeneration, err.Error(), verificationMaxAttempts); ferr != nil {
					log.Printf("[verifier] 记录失败状态: %v", ferr)
				}
			}
		}(job)
	}
}
