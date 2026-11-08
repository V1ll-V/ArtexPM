package server

import (
	"context"
	"encoding/json"
	"log"

	"time"

	"github.com/Autumn-27/artex/db"
)

// ============================================================================
// V1:验收通过事件驱动的报告工作流,以及内置触发器迁移。
//
// 关键约束:
//   - 事件表不使用水位线。水位线在跳过分支之前就会推进,被跳过的事件将永久
//     丢失("先候选、后通过"的乱序场景必然踩中)。这里用"未处理行 + SKIP LOCKED"
//     的工作队列。
//   - verdict_events 的唯一消费者是持久化扇出器 FanOutVerdictEvents:它在一个
//     事务里创建下游任务并确认事件。各下游任务(event_jobs)有自己的幂等键,
//     不会因为"第一个消费者处理完"而让其他消费者丢事件。
//   - 正式报告仍然要过 SetFindingReportGated 的门禁,遗留触发器即使启动
//     Reporter 也拿不到报告写入权限。
// ============================================================================

const (
	// reportJobLease 是下游报告任务的租约。模型调用不计入数据库事务,租约只
	// 保证"过期执行者不能提交"。
	reportJobLease = 10 * time.Minute
	// reportJobMaxAttempts 限制重试次数,超过则落 failed 并保留可见错误。
	reportJobMaxAttempts = 3
)

// MigrateReporterTriggerToVerdictEvent is the compatibility entry for the
// transactional migration. Unknown triggers remain intact and visible for review.
func (s *Server) MigrateReporterTriggerToVerdictEvent() {
	if s == nil || s.m == nil || s.m.pg == nil {
		return
	}
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := s.migrateVerificationConfig(ctx); err != nil {
		log.Printf("[verdict] configuration migration: %v", err)
	}
}

// fireVerdictWorkflow 驱动验收事件的两段式工作流:
//
//	① 扇出:未处理事件 → 下游任务(原子)
//	② 领取 report_run 任务 → 启动 Reporter(至少一次;过期执行者不能提交结果)
func (sc *Scheduler) fireVerdictWorkflow() {
	if sc == nil || sc.pg == nil {
		return
	}
	// Configuration migration runs before scheduling. Unknown/custom triggers
	// remain visible for review; their old write tools remain fail-closed.
	ctx := sc.verificationCtx
	if ctx == nil && sc.s != nil {
		ctx = sc.s.ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	sc.runVerificationQueue()
	// Goal proof evaluation remains available when optional finding/report
	// automation is disabled; it is needed for ordinary task completion too.
	if sc.s != nil && sc.s.engine != nil && sc.s.engine.lifecycleReady != nil && !sc.s.engine.lifecycleReady() {
		return
	}
	if _, _, err := sc.pg.FanOutVerdictEvents(ctx, 20); err != nil {
		log.Printf("[verdict] event fan-out: %v", err)
		return
	}
	sc.runReportQueue()
}

// Compatibility entry point: this now executes the persistent report workflow,
// never the in-memory trigger queue and never acknowledges an enqueue.
func (sc *Scheduler) startReportRun(job *db.VerificationJob) error {
	if sc == nil || sc.s == nil {
		return errReportWriterUnavailable
	}
	ctx := sc.verificationCtx
	if ctx == nil {
		ctx = sc.s.ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return sc.s.processReportJob(ctx, job)
}

// reportJobFindingID 仅用于日志/测试可读性。
func reportJobFindingID(job *db.VerificationJob) int64 {
	var payload struct {
		FindingID int64 `json:"finding_id"`
	}
	_ = json.Unmarshal(job.Result, &payload)
	return payload.FindingID
}

// findingGateAllowsReport 供其它入口复用同一判据(存在性 + 判定有效 + 版本一致)。
func (s *Server) findingGateAllowsReport(ctx context.Context, findingID int64) bool {
	if s == nil || s.m == nil || s.m.pg == nil {
		return false
	}
	row, ok, err := s.m.pg.FindingVerdictByID(ctx, findingID)
	if err != nil || !ok {
		return false
	}
	return db.FindingVerdictEffective(row.State())
}
