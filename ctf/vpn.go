package ctf

import (
	"context"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/artifacts"
	"github.com/Autumn-27/artex/ctfrunner"
)

func (s *Service) sessionSpec(ctx context.Context, task, sessionIntent int64, m artifacts.Manifest) (ctfrunner.SessionSpec, error) {
	spec := ctfrunner.SessionSpec{TaskID: task, IntentID: sessionIntent, InputHash: Hash(m)}
	if s.DB == nil {
		return spec, nil
	}
	_, vpnHash, _, err := s.DB.TaskCTFVPN(ctx, task)
	if err != nil {
		return spec, fmt.Errorf("读取 CTF VPN 状态失败：%w", err)
	}
	spec.VPNHash = strings.TrimSpace(vpnHash)
	return spec, nil
}

// CleanupTask removes all managed runner containers, VPN sidecars, and volumes for task.
func (s *Service) CleanupTask(ctx context.Context, task int64) error {
	if s == nil || s.Runner == nil || !s.Runner.Configured() || task <= 0 {
		return nil
	}
	return s.Runner.DeleteTaskResources(ctx, task)
}
