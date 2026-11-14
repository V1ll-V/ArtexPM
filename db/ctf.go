package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type CTFExecution struct {
	ID            string          `json:"id"`
	TaskID        int64           `json:"task_id"`
	IntentID      int64           `json:"intent_id"`
	InputHash     string          `json:"input_hash"`
	Command       string          `json:"command"`
	ExitCode      int             `json:"exit_code"`
	StdoutPath    string          `json:"-"`
	StderrPath    string          `json:"-"`
	StdoutSHA     string          `json:"stdout_sha"`
	StderrSHA     string          `json:"stderr_sha"`
	StdoutExcerpt string          `json:"stdout"`
	StderrExcerpt string          `json:"stderr"`
	Error         string          `json:"error,omitempty"`
	Truncated     bool            `json:"truncated"`
	Files         json.RawMessage `json:"files"`
	Environment   json.RawMessage `json:"environment"`
	StartedAt     time.Time       `json:"started_at"`
	FinishedAt    *time.Time      `json:"finished_at,omitempty"`
}
const (
	CTFCandidateFlag         = "flag"
	CTFCandidateExploitProof = "exploit_proof"
)

type CTFCandidate struct {
	ID          int64     `json:"id"`
	TaskID      int64     `json:"task_id"`
	ExecutionID string    `json:"execution_id"`
	InputHash   string    `json:"input_hash"`
	Value       string    `json:"value"`
	State       string    `json:"state"`
	Notes       string    `json:"notes"`
	Kind        string    `json:"kind"`
	Revision    int64     `json:"revision"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
type CTFGoalProof struct {
	InputHash  string         `json:"input_hash"`
	VerifyMode string         `json:"verify_mode,omitempty"`
	Accepted   []CTFCandidate `json:"accepted"`
}

func (s *ExplorationStore) Database() *DB { return s.db }

func (d *DB) SyncCTFInput(ctx context.Context, taskID int64, hash string) error {
	return d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockTaskEvidenceTx(tx, taskID); err != nil {
			return err
		}
		var old, mode string
		if err := tx.QueryRowContext(ctx, `SELECT mode,ctf_input_hash FROM tasks WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, taskID).Scan(&mode, &old); err != nil {
			return err
		}
		if mode != "ctf" {
			return errors.New("not a CTF task")
		}
		if old == hash {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE tasks SET ctf_input_hash=$2 WHERE id=$1`, taskID, hash); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE ctf_candidates SET state='stale',revision=revision+1,updated_at=now() WHERE task_id=$1 AND input_hash<>$2 AND state<>'stale'`, taskID, hash); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='open',blocked_reason='CTF 输入已更新，请重新验证' WHERE exploration_id=(SELECT exploration_id FROM tasks WHERE id=$1) AND kind='goal' AND state='met'`, taskID)
		if err == nil {
			err = reopenRevokedCTFCompletionTx(ctx, tx, taskID)
		}
		return err
	})
}

func (d *DB) SaveCTFExecution(ctx context.Context, e *CTFExecution) error {
	if e.Files == nil {
		e.Files = json.RawMessage("[]")
	}
	if e.Environment == nil {
		e.Environment = json.RawMessage(`{}`)
	}
	cmd := utf8Clean(e.Command)
	stdoutPath := utf8Clean(e.StdoutPath)
	stderrPath := utf8Clean(e.StderrPath)
	stdoutExcerpt := utf8Clean(e.StdoutExcerpt)
	stderrExcerpt := utf8Clean(e.StderrExcerpt)
	errMsg := utf8Clean(e.Error)
	files := jsonbClean(e.Files)
	env := jsonbClean(e.Environment)
	_, err := d.ExecContext(ctx, `INSERT INTO ctf_executions(id,task_id,intent_id,input_hash,command,exit_code,stdout_path,stderr_path,stdout_sha,stderr_sha,stdout_excerpt,stderr_excerpt,error,truncated,files,started_at,finished_at,environment)
 SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,$16,$17,$18::jsonb WHERE EXISTS(SELECT 1 FROM tasks WHERE id=$2 AND mode='ctf' AND deleted_at IS NULL)
 ON CONFLICT(id) DO NOTHING`, e.ID, e.TaskID, e.IntentID, e.InputHash, cmd, e.ExitCode, stdoutPath, stderrPath, e.StdoutSHA, e.StderrSHA, stdoutExcerpt, stderrExcerpt, errMsg, e.Truncated, string(files), e.StartedAt, e.FinishedAt, string(env))
	return err
}

const ctfExecCols = `id,task_id,intent_id,input_hash,command,exit_code,stdout_path,stderr_path,stdout_sha,stderr_sha,stdout_excerpt,stderr_excerpt,error,truncated,files,started_at,finished_at,environment`

func scanCTFExec(s interface{ Scan(...any) error }) (CTFExecution, error) {
	var e CTFExecution
	err := s.Scan(&e.ID, &e.TaskID, &e.IntentID, &e.InputHash, &e.Command, &e.ExitCode, &e.StdoutPath, &e.StderrPath, &e.StdoutSHA, &e.StderrSHA, &e.StdoutExcerpt, &e.StderrExcerpt, &e.Error, &e.Truncated, &e.Files, &e.StartedAt, &e.FinishedAt, &e.Environment)
	return e, err
}
func (d *DB) CTFExecution(ctx context.Context, taskID int64, id string) (CTFExecution, error) {
	return scanCTFExec(d.QueryRowContext(ctx, `SELECT `+ctfExecCols+` FROM ctf_executions WHERE task_id=$1 AND id=$2`, taskID, id))
}
func (d *DB) CTFExecutions(ctx context.Context, taskID int64) ([]CTFExecution, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+ctfExecCols+` FROM ctf_executions WHERE task_id=$1 ORDER BY started_at DESC,id DESC LIMIT 100`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CTFExecution{}
	for rows.Next() {
		e, err := scanCTFExec(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) AddCTFCandidate(ctx context.Context, taskID int64, execID, value string) (int64, error) {
	return d.addCTFCandidate(ctx, taskID, execID, value, "", CTFCandidateFlag, false)
}

// Do not resurface a resolved answer when a later command prints it again.
// Explicit manual submissions remain possible.
func (d *DB) AddCTFOutputCandidate(ctx context.Context, taskID int64, execID, value string) (int64, error) {
	return d.addCTFCandidate(ctx, taskID, execID, value, "", CTFCandidateFlag, true)
}

// AddCTFExploitProofCandidate records an operator-verifiable exploit proof
// candidate grounded in a real container execution.
func (d *DB) AddCTFExploitProofCandidate(ctx context.Context, taskID int64, execID, proofSummary, detail string) (int64, error) {
	return d.addCTFCandidate(ctx, taskID, execID, proofSummary, detail, CTFCandidateExploitProof, false)
}

func (d *DB) addCTFCandidate(ctx context.Context, taskID int64, execID, value, notes, kind string, skipRejected bool) (int64, error) {
	value = utf8Clean(strings.TrimSpace(value))
	notes = utf8Clean(strings.TrimSpace(notes))
	if value == "" || len(value) > 4096 {
		return 0, errors.New("候选答案或证明摘要长度无效")
	}
	if len(notes) > 8192 {
		return 0, errors.New("证明详情过长")
	}
	if kind != CTFCandidateExploitProof {
		kind = CTFCandidateFlag
	}
	var id int64
	err := d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockTaskEvidenceTx(tx, taskID); err != nil {
			return err
		}
		err := tx.QueryRowContext(ctx, `INSERT INTO ctf_candidates(task_id,execution_id,input_hash,value,notes,kind,state)
 SELECT e.task_id,e.id,e.input_hash,$3,$4,$5,CASE WHEN e.input_hash=t.ctf_input_hash THEN 'candidate' ELSE 'stale' END FROM ctf_executions e JOIN tasks t ON t.id=e.task_id WHERE e.task_id=$1 AND e.id=$2 AND t.deleted_at IS NULL
 AND (NOT $6 OR NOT EXISTS(SELECT 1 FROM ctf_candidates c WHERE c.task_id=e.task_id AND c.input_hash=e.input_hash AND c.value=$3 AND c.state IN ('rejected','accepted')))
 ON CONFLICT(task_id,execution_id,value) DO UPDATE SET value=excluded.value,kind=excluded.kind,notes=CASE WHEN excluded.notes<>'' THEN excluded.notes ELSE ctf_candidates.notes END,state=CASE WHEN ctf_candidates.state='rejected' AND excluded.kind='exploit_proof' THEN 'candidate' ELSE ctf_candidates.state END,revision=ctf_candidates.revision+1,updated_at=now() RETURNING id`, taskID, execID, value, notes, kind, skipRejected).Scan(&id)
		if skipRejected && errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	})
	return id, err
}

const ctfCandidateCols = `id,task_id,execution_id,input_hash,value,state,notes,revision,created_at,updated_at,kind`

func scanCTFCandidate(s interface{ Scan(...any) error }) (CTFCandidate, error) {
	var c CTFCandidate
	err := s.Scan(&c.ID, &c.TaskID, &c.ExecutionID, &c.InputHash, &c.Value, &c.State, &c.Notes, &c.Revision, &c.CreatedAt, &c.UpdatedAt, &c.Kind)
	if c.Kind == "" {
		c.Kind = CTFCandidateFlag
	}
	return c, err
}
func (d *DB) CTFCandidates(ctx context.Context, taskID int64) ([]CTFCandidate, error) {
	rows, err := d.QueryContext(ctx, `SELECT `+ctfCandidateCols+` FROM ctf_candidates WHERE task_id=$1 ORDER BY id DESC LIMIT 100`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CTFCandidate{}
	for rows.Next() {
		c, err := scanCTFCandidate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (d *DB) DecideCTFCandidate(ctx context.Context, taskID, id, expectedRevision int64, state, notes string, completeTask ...bool) (CTFCandidate, error) {
	var out CTFCandidate
	if state != "accepted" && state != "rejected" {
		return out, errors.New("无效的确认结果")
	}
	if len(notes) > 8192 {
		return out, errors.New("备注过长")
	}
	finish := len(completeTask) > 0 && completeTask[0]
	if finish && state != "accepted" {
		return out, errors.New("只有确认正确的 Flag 才能完成任务")
	}
	err := d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := LockTaskEvidenceTx(tx, taskID); err != nil {
			return err
		}
		c, err := scanCTFCandidate(tx.QueryRowContext(ctx, `SELECT `+ctfCandidateCols+` FROM ctf_candidates WHERE task_id=$1 AND id=$2 FOR UPDATE`, taskID, id))
		if err != nil {
			return err
		}
		var current string
		if err = tx.QueryRowContext(ctx, `SELECT ctf_input_hash FROM tasks WHERE id=$1 AND mode='ctf' AND deleted_at IS NULL FOR UPDATE`, taskID).Scan(&current); err != nil {
			return err
		}
		if c.Revision != expectedRevision {
			return errors.New("候选记录已变化，请刷新后重试")
		}
		if c.InputHash != current {
			return errors.New("候选来自旧输入版本，不能确认")
		}
		out, err = scanCTFCandidate(tx.QueryRowContext(ctx, `UPDATE ctf_candidates SET state=$3,notes=$4,revision=revision+1,updated_at=now() WHERE task_id=$1 AND id=$2 RETURNING `+ctfCandidateCols, taskID, id, state, notes))
		if err != nil {
			return err
		}
		// Identical pending values from parallel executions represent the same
		// answer. Apply the human decision together so waiting can end.
		if _, err = tx.ExecContext(ctx, `UPDATE ctf_candidates SET state=$6,notes=$4,revision=revision+1,updated_at=now()
 WHERE task_id=$1 AND input_hash=$2 AND value=$3 AND (state='candidate' OR ($6='rejected' AND state='accepted')) AND id<>$5`, taskID, c.InputHash, c.Value, notes, c.ID, state); err != nil {
			return err
		}
		if state == "accepted" {
			summaryPrefix := "人工确认本题候选答案："
			if c.Kind == CTFCandidateExploitProof {
				summaryPrefix = "人工确认本题漏洞利用已在平台验证通过："
			}
			payload, _ := json.Marshal(map[string]any{"summary": summaryPrefix + c.Value, "detail": notes, "subtype": "ctf_answer", "kind": c.Kind, "candidate_id": c.ID, "execution_id": c.ExecutionID, "input_hash": c.InputHash, "verification": "operator_confirmed"})
			var expID, factID int64
			err = tx.QueryRowContext(ctx, `INSERT INTO exploration_nodes(exploration_id,kind,payload,state,origin) SELECT exploration_id,'fact',$2::jsonb,'confirmed','human' FROM tasks WHERE id=$1 RETURNING exploration_id, id`, taskID, string(payload)).Scan(&expID, &factID)
			if err == nil && expID > 0 && factID > 0 {
				var intentID int64
				if c.ExecutionID != "" {
					_ = tx.QueryRowContext(ctx, `SELECT intent_id FROM ctf_executions WHERE task_id=$1 AND id=$2`, taskID, c.ExecutionID).Scan(&intentID)
				}
				srcID := intentID
				if srcID <= 0 {
					_ = tx.QueryRowContext(ctx, `SELECT id FROM exploration_nodes WHERE exploration_id=$1 AND kind='fact' AND state='origin' ORDER BY id LIMIT 1`, expID).Scan(&srcID)
				}
				if srcID > 0 {
					_, _ = tx.ExecContext(ctx, `INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES ($1,$2,$3,$4) ON CONFLICT (exploration_id,src_id,rel,dst_id) DO NOTHING`, expID, srcID, RelYields, factID)
				}
				if !finish && intentID > 0 {
					_, _ = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='done',content_version=content_version+1 WHERE id=$1 AND exploration_id=$2 AND kind='intent' AND state='open'`, intentID, expID)
				}
				_, _ = tx.ExecContext(ctx, `UPDATE exploration_nodes SET blocked_reason='' WHERE exploration_id=$1 AND kind='goal' AND state='open' AND blocked_reason='CTF 答案确认已撤销，请重新验证'`, expID)
			}
		}
		if state == "rejected" && c.State == "accepted" {
			_, err = tx.ExecContext(ctx, `UPDATE exploration_nodes SET state='open',blocked_reason='CTF 答案确认已撤销，请重新验证' WHERE exploration_id=(SELECT exploration_id FROM tasks WHERE id=$1) AND kind='goal' AND state='met'`, taskID)
			if err == nil {
				err = reopenRevokedCTFCompletionTx(ctx, tx, taskID)
			}
		}
		if err == nil && finish {
			err = completeCTFSubmissionTx(ctx, tx, out)
		}
		return err
	})
	return out, err
}

func ctfGoalProofTx(ctx context.Context, tx *sql.Tx, taskID int64) (*CTFGoalProof, error) {
	if taskID == 0 {
		return nil, nil
	}
	var mode, hash, rawVerify, desc, goal string
	err := tx.QueryRowContext(ctx, `SELECT mode,ctf_input_hash,COALESCE(ctf_verify_mode,''),COALESCE(description,''),COALESCE(goal,'') FROM tasks WHERE id=$1`, taskID).Scan(&mode, &hash, &rawVerify, &desc, &goal)
	if err != nil {
		return nil, err
	}
	if mode != "ctf" {
		return nil, nil
	}
	p := &CTFGoalProof{
		InputHash:  hash,
		VerifyMode: EffectiveCTFVerifyMode(rawVerify, desc, goal),
		Accepted:   []CTFCandidate{},
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+ctfCandidateCols+` FROM ctf_candidates WHERE task_id=$1 AND state='accepted' AND input_hash=$2 ORDER BY id`, taskID, hash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		c, err := scanCTFCandidate(rows)
		if err != nil {
			return nil, err
		}
		p.Accepted = append(p.Accepted, c)
	}
	return p, rows.Err()
}

func (d *DB) CTFTaskIDsForWP(ctx context.Context) ([]int64, error) {
	rows, err := d.QueryContext(ctx, `SELECT id FROM tasks WHERE mode='ctf' AND deleted_at IS NULL AND status IN ('done','failed','timeout') ORDER BY id DESC LIMIT 20`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func RequireCTFAcceptedFlag(b *EvidenceBundle) error {
	if b.CTF == nil {
		return nil
	}
	verifyMode := strings.ToLower(strings.TrimSpace(b.CTF.VerifyMode))
	if verifyMode == "" {
		verifyMode = CTFVerifyFlag
	}
	if b.CTF.InputHash == "" {
		if verifyMode == CTFVerifyExploitProof {
			return fmt.Errorf("CTF 漏洞利用证明尚缺当前输入版本的平台验证确认；命令输出和模型回复不能替代平台验证")
		}
		return fmt.Errorf("CTF 目标尚缺当前输入版本的可信答案确认；正则匹配和模型回复不能作为最终成功依据")
	}
	var hasFlag, hasProof bool
	for _, c := range b.CTF.Accepted {
		if c.Kind == CTFCandidateExploitProof {
			hasProof = true
		} else {
			hasFlag = true
		}
	}
	switch verifyMode {
	case CTFVerifyExploitProof:
		if !hasProof {
			return fmt.Errorf("CTF 漏洞利用证明尚缺用户在赛题平台验证后的确认；命令输出和模型回复不能替代平台验证")
		}
	case CTFVerifyFlagAndExploit:
		if !hasFlag || !hasProof {
			return fmt.Errorf("复合验收 CTF 目标尚需同时确认「Flag」与「漏洞利用证明」后方可通过终局验收")
		}
	default:
		if !hasFlag && len(b.CTF.Accepted) == 0 {
			return fmt.Errorf("CTF 目标尚缺当前输入版本的可信答案确认；正则匹配和模型回复不能作为最终成功依据")
		}
	}
	return nil
}
