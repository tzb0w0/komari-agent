package server

// agentSettings.go —— 从面板拉取采集参数
//
// 线路判定间隔、TCP 重传采样窗口由面板「设置 → 监控」统一配置，
// 探针启动时拉取一次，之后每 15 分钟同步一次，实现「改一次全节点生效」。

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/komari-monitor/komari-agent/dnsresolver"
	monitoring "github.com/komari-monitor/komari-agent/monitoring/unit"
)

type agentSettings struct {
	LineDetectIntervalHours   int `json:"line_detect_interval_hours"`
	RetransmitIntervalMinutes int `json:"retransmit_interval_minutes"`
}

type agentSettingsEnvelope struct {
	Status  string        `json:"status"`
	Message string        `json:"message"`
	Data    agentSettings `json:"data"`
}

// ApplyAgentSettings 从面板拉取并应用采集参数。失败时仅记录日志，保留本地默认值。
func ApplyAgentSettings() error {
	if flags.Endpoint == "" || flags.Token == "" {
		return fmt.Errorf("endpoint 或 token 尚未就绪")
	}

	url := strings.TrimSuffix(flags.Endpoint, "/") + "/api/clients/agent-settings?token=" + flags.Token
	client := dnsresolver.GetHTTPClientWithPreference(15*time.Second, flags.PreferIPVersion)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var env agentSettingsEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("解析返回失败: %w", err)
	}
	if env.Status != "" && env.Status != "success" {
		return fmt.Errorf("面板返回错误: %s", env.Message)
	}

	hours := env.Data.LineDetectIntervalHours
	if hours <= 0 {
		hours = 24
	}
	minutes := env.Data.RetransmitIntervalMinutes
	if minutes <= 0 {
		minutes = 30
	}

	monitoring.SetLineDetectInterval(time.Duration(hours) * time.Hour)
	monitoring.SetRetransmitInterval(time.Duration(minutes) * time.Minute)
	log.Printf("采集参数已同步：线路判定 %d 小时 / 重传窗口 %d 分钟", hours, minutes)
	return nil
}

// StartAgentSettingsSync 启动定时同步（首次立即执行）。
func StartAgentSettingsSync(interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	go func() {
		if err := ApplyAgentSettings(); err != nil {
			log.Printf("拉取采集参数失败，沿用默认值：%v", err)
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if err := ApplyAgentSettings(); err != nil {
				log.Printf("同步采集参数失败：%v", err)
			}
		}
	}()
}
