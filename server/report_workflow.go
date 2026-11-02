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
	reportConcurrency      = 2
	reportExecutionTimeout = 5 * time.Minute
)

var errReportWriterUnavailable = errors.New("报告执行器未配置")

func (s *Server) SetReportWriter(writer agent.ReportWriter) {
	if s != nil {
		s.cfgMu.Lock()
		s.reportWriter = writer
		s.cfgMu.Unlock()
	}
}
func (s *Server) currentReportWriter() agent.ReportWriter {
	if s == nil {
		return nil
	}
	s.cfgMu.Lock()
	injected, provider := s.reportWriter, s.llmProv
	s.cfgMu.Unlock()
	if injected != nil {
		return injected
	}
	if s.m != nil && s.m.pg != nil {
		reporter, err := s.m.pg.GetAgentByKey("reporter")
		if err != nil || (reporter != nil && !reporter.Enabled) {
			return nil
		}
		if profile := s.effectiveProfileForAgent("reporter", nil); profile != nil {
			selected, _, ok := s.providerForProfile(*profile)
			if !ok {
				return nil
			}
			provider = selected
		}
	}
	if provider == nil {
		return nil
	}
	return &agent.LLMReportWriter{Prov: provider}
}

func (s *Server) reportSystemPrompt() (string, error) {
	templateText := ""
	if s.m != nil && s.m.pg != nil {
		reporter, err := s.m.pg.GetAgentByKey("reporter")
		if err != nil {
			return "", err
		}
		if reporter != nil {
			templateText, err = s.m.pg.CurrentPrompt(reporter.ID)
			if err != nil {
				return "", err
			}
		}
	}
	return agent.ReportSystemPrompt(templateText, s.m.dir)
}

func (s *Server) processReportJob(ctx context.Context, job *db.VerificationJob) error {
	writer := s.currentReportWriter()
	if writer == nil {
		return errReportWriterUnavailable
	}
	prompt, err := s.reportSystemPrompt()
	if err != nil {
		return err
	}
	return processReportJobWith(ctx, s.m.pg, writer, job, prompt, s.evidenceStore().LoadVerificationBodies)
}

func reportObsolete(err error) bool {
	return errors.Is(err, db.ErrReportStale) || errors.Is(err, db.ErrVerdictNotSupported) || errors.Is(err, db.ErrFindingNotFound) ||
		errors.Is(err, db.ErrReportSubjectMismatch) || errors.Is(err, db.ErrTaskArchiveState)
}

func processReportJobWith(ctx context.Context, pg *db.DB, writer agent.ReportWriter, job *db.VerificationJob, prompt string, loaders ...verificationBodyLoader) error {
	if pg == nil || job == nil || writer == nil {
		return errReportWriterUnavailable
	}
	run, err := pg.PrepareReportRun(ctx, job.ID, job.LeaseGeneration)
	if err != nil {
		if errors.Is(err, db.ErrReportLeaseLost) {
			return nil
		}
		if reportObsolete(err) {
			return pg.SupersedeReportJob(ctx, job.ID, job.LeaseGeneration, err.Error())
		}
		return err
	}
	input := &db.ReportExecutionInput{SystemPrompt: prompt, Snapshot: run.Snapshot}
	if len(loaders) > 0 && loaders[0] != nil {
		if err = loaders[0](ctx, input.Snapshot.Evidence); err != nil {
			return err
		}
	}
	input, err = pg.RecordReportExecutionInput(ctx, run, input)
	if err != nil {
		return err
	}
	if concrete, ok := writer.(*agent.LLMReportWriter); ok {
		local := *concrete
		observe := local.ObserveResponse
		local.ObserveResponse = func(ctx context.Context, raw string) error {
			if err := pg.RecordReportOutput(ctx, run, raw); err != nil {
				return err
			}
			if observe != nil {
				return observe(ctx, raw)
			}
			return nil
		}
		writer = &local
	}
	report, err := writer.WriteReport(ctx, input)
	if err != nil {
		return err
	}
	_, err = pg.SetFindingReportGated(db.WithReportRun(ctx, run), run.Snapshot.NodeID, report, &run.Snapshot.EvidenceVersion)
	if errors.Is(err, db.ErrReportLeaseLost) {
		return nil
	}
	if reportObsolete(err) {
		return pg.SupersedeReportJob(ctx, job.ID, job.LeaseGeneration, err.Error())
	}
	return err
}

func (sc *Scheduler) runReportQueue() {
	if sc == nil || sc.pg == nil || sc.s == nil {
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
	if err := sc.pg.RecoverReportJobs(parent, reportJobMaxAttempts); err != nil {
		log.Printf("[reporter] recovery: %v", err)
		return
	}
	if sc.s.currentReportWriter() == nil {
		return
	}
	if sc.reportSlots == nil {
		sc.reportSlots = make(chan struct{}, reportConcurrency)
	}
	limit := reportConcurrency
	if reporter, err := sc.pg.GetAgentByKey("reporter"); err != nil {
		return
	} else if reporter != nil {
		if reporter.TriggerRunMode != "parallel" {
			limit = 1
		} else if reporter.TriggerMaxParallel > 0 {
			limit = min(limit, reporter.TriggerMaxParallel)
		}
	}
	timeout := reportExecutionTimeout
	if seconds := sc.s.agentRunSeconds("reporter"); seconds > 0 {
		timeout = min(timeout, time.Duration(seconds)*time.Second)
	}
	for {
		if len(sc.reportSlots) >= limit {
			return
		}
		select {
		case sc.reportSlots <- struct{}{}:
		default:
			return
		}
		job, err := sc.pg.ClaimEventJob(parent, db.EventJobReportRun, reportJobLease, reportJobMaxAttempts)
		if err != nil || job == nil {
			<-sc.reportSlots
			if err != nil {
				log.Printf("[reporter] claim: %v", err)
			}
			return
		}
		sc.reportWG.Add(1)
		go func(job *db.VerificationJob) {
			defer sc.reportWG.Done()
			defer func() { <-sc.reportSlots }()
			ctx, cancel := context.WithTimeout(parent, timeout)
			defer cancel()
			var executionErr error
			defer func() {
				if recovered := recover(); recovered != nil {
					executionErr = fmt.Errorf("reporter panic: %v", recovered)
				}
				if executionErr != nil {
					cleanup, stop := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
					defer stop()
					attemptLimit := reportJobMaxAttempts
					if errors.Is(executionErr, agent.ErrReportNeedsEvidence) {
						attemptLimit = 1
					} // identical material cannot fix a semantic evidence gap
					if err := sc.pg.FailEventJob(cleanup, job.ID, job.LeaseGeneration, executionErr.Error(), attemptLimit); err != nil {
						log.Printf("[reporter] persist failure: %v", err)
					}
				}
			}()
			executionErr = sc.s.processReportJob(ctx, job)
		}(job)
	}
}
