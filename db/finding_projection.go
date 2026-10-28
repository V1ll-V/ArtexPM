package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// FindingLifecycle is read with the finding row, so display and report validity
// cannot accidentally combine different revisions from separate queries.
type FindingLifecycle struct {
	VerdictState
	ProposedClaim         string          `json:"proposed_claim"`
	AcceptedClaim         string          `json:"accepted_claim"`
	AcceptedDetail        json.RawMessage `json:"accepted_detail"`
	HasReport             bool            `json:"has_report"`
	ReportInputRevision   int64           `json:"report_input_revision"`
	ReportVerdictRevision int64           `json:"report_verdict_revision"`
	ReportHumanRevision   int64           `json:"report_human_revision"`
	ReportPolicyVersion   string          `json:"report_policy_version"`
	ReportRunID           int64           `json:"report_run_id"`
}

const findingLifecycleColumns = `jsonb_build_object(
 'technical_verdict',f.technical_verdict,'input_revision',f.input_revision,
 'verdict_revision',f.verdict_revision,'human_revision',f.human_revision,
 'verdict_input_revision',f.verdict_input_revision,'verdict_policy_version',f.verdict_policy_version,
 'legacy_source',f.legacy_source,'proposed_claim',f.proposed_claim,'accepted_claim',f.accepted_claim,
 'accepted_detail',f.accepted_detail,'has_report',f.report<>'',
 'report_input_revision',f.report_input_revision,'report_verdict_revision',f.report_verdict_revision,
 'report_human_revision',f.report_human_revision,'report_policy_version',f.report_policy_version,
 'report_run_id',COALESCE(f.report_run_id,0))`

type FindingProjection struct {
	VerdictDetail    json.RawMessage `json:"verdict_detail"`
	TechnicalVerdict string          `json:"technical_verdict"`
	Effective        bool            `json:"effective"`
	VerdictStale     bool            `json:"verdict_stale"`
	ProposedClaim    string          `json:"proposed_claim"`
	AcceptedClaim    string          `json:"accepted_claim"`
	AcceptedDetail   json.RawMessage `json:"accepted_detail"`
	DisplayClaim     string          `json:"display_claim"`
	DisplaySeverity  string          `json:"display_severity"`
	LegacySource     string          `json:"legacy_source,omitempty"`
	InputRevision    int64           `json:"input_revision"`
	VerdictRevision  int64           `json:"verdict_revision"`
	HumanRevision    int64           `json:"human_revision"`
}

func (f *DBFinding) Projection() FindingProjection {
	l := f.Lifecycle
	p := FindingProjection{TechnicalVerdict: l.TechnicalVerdict, Effective: FindingVerdictEffective(l.VerdictState),
		VerdictDetail: json.RawMessage(`{}`),
		ProposedClaim: l.ProposedClaim, AcceptedDetail: json.RawMessage(`{}`), DisplaySeverity: f.Severity,
		LegacySource: l.LegacySource, InputRevision: l.InputRevision, VerdictRevision: l.VerdictRevision, HumanRevision: l.HumanRevision}
	if p.TechnicalVerdict == "" {
		p.TechnicalVerdict = VerdictUnverified
	}
	if len(l.AcceptedDetail) > 0 {
		p.VerdictDetail = l.AcceptedDetail
	}
	if p.ProposedClaim == "" {
		p.ProposedClaim = f.Summary
	}
	p.DisplayClaim = p.ProposedClaim
	p.VerdictStale = l.VerdictRevision > 0 && (l.VerdictInputRevision != l.InputRevision || l.VerdictPolicyVersion != VerdictPolicyVersion)
	if p.Effective {
		p.DisplaySeverity = ""
		p.AcceptedClaim, p.DisplayClaim = l.AcceptedClaim, l.AcceptedClaim
		if len(l.AcceptedDetail) > 0 {
			p.AcceptedDetail = l.AcceptedDetail
		}
		var detail struct {
			Severity         string `json:"severity"`
			AcceptedSeverity string `json:"accepted_severity"`
		}
		if json.Unmarshal(l.AcceptedDetail, &detail) == nil {
			if ValidSeverity(detail.AcceptedSeverity) {
				p.DisplaySeverity = detail.AcceptedSeverity
			} else if ValidSeverity(detail.Severity) {
				p.DisplaySeverity = detail.Severity
			}
		}
	}
	return p
}

func (f *DBFinding) ReportIsStale() bool {
	l := f.Lifecycle
	return (l.HasReport || f.Report != "") && (!FindingVerdictEffective(l.VerdictState) ||
		l.ReportRunID <= 0 || l.ReportInputRevision != l.InputRevision || l.ReportVerdictRevision != l.VerdictRevision ||
		l.ReportHumanRevision != l.HumanRevision || l.ReportPolicyVersion != VerdictPolicyVersion || f.ReportEvidenceVersion != f.EvidenceVersion)
}

// RefreshFindingLifecycleTx makes export validity part of the same evidence
// transaction as the body/binding snapshot. No derived value is written back.
func RefreshFindingLifecycleTx(tx *sql.Tx, f *DBFinding) error {
	var raw []byte
	if err := tx.QueryRow(`SELECT `+findingLifecycleColumns+` FROM findings f WHERE f.id=$1`, f.ID).Scan(&raw); err != nil {
		return err
	}
	return json.Unmarshal(raw, &f.Lifecycle)
}

// IDs come from nodes already authorized by the owning/source-task read path.
// The projection is derived; it must never replace a candidate's input payload.
func (s *ExplorationStore) FindingProjections(nodeIDs []int64) (map[int64]FindingProjection, error) {
	out := map[int64]FindingProjection{}
	if len(nodeIDs) == 0 {
		return out, nil
	}
	args := make([]any, len(nodeIDs))
	ph := make([]string, len(nodeIDs))
	for i, id := range nodeIDs {
		args[i] = id
		ph[i] = fmt.Sprintf("$%d", i+1)
	}
	rows, err := s.db.Query(`SELECT f.node_id,f.summary,f.severity,`+findingLifecycleColumns+` FROM findings f WHERE f.node_id IN (`+strings.Join(ph, ",")+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var raw []byte
		f := &DBFinding{}
		if err = rows.Scan(&id, &f.Summary, &f.Severity, &raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &f.Lifecycle); err != nil {
			return nil, err
		}
		out[id] = f.Projection()
	}
	return out, rows.Err()
}
