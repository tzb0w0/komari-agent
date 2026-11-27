package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/komari-monitor/komari-agent/dnsresolver"
	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
	"github.com/komari-monitor/komari-agent/ws"
	ping "github.com/prometheus-community/pro-bing"
)

func resolveIP(target string) (string, error) {
	// 如果已经是 IP 地址，直接返回
	if ip := net.ParseIP(target); ip != nil {
		return target, nil
	}
	// 解析域名到 IP
	addrs, err := net.LookupHost(target)
	if err != nil || len(addrs) == 0 {
		return "", errors.New("failed to resolve target")
	}
	return addrs[0], nil // 返回第一个解析的 IP
}

func icmpPing(target string, timeout time.Duration) (int64, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	// For ICMP, we only need the host/IP, port is irrelevant.
	// If the host is an IPv6 literal, it might be wrapped in brackets.
	host = strings.Trim(host, "[]")

	// 先解析 IP 地址
	ip, err := resolveIP(host)
	if err != nil {
		return -1, err
	}

	pinger, err := ping.NewPinger(ip)
	if err != nil {
		return -1, err
	}
	pinger.Count = 1
	pinger.Timeout = timeout
	pinger.SetPrivileged(true)
	err = pinger.Run()
	if err != nil {
		return -1, err
	}
	stats := pinger.Statistics()
	if stats.PacketsRecv == 0 {
		return -1, errors.New("no packets received")
	}
	return stats.AvgRtt.Milliseconds(), nil
}

func tcpPing(target string, timeout time.Duration) (int64, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		// No port, assume port 80
		host = target
		port = "80"
	}

	// If the host is an IPv6 literal, it might be wrapped in brackets.
	host = strings.Trim(host, "[]")

	ip, err := resolveIP(host)
	if err != nil {
		return -1, err
	}

	targetAddr := net.JoinHostPort(ip, port)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", targetAddr, timeout)
	if err != nil {
		return -1, err
	}
	defer conn.Close()
	return time.Since(start).Milliseconds(), nil
}

func httpPing(target string, timeout time.Duration) (int64, error) {
	// Handle raw IPv6 address for URL
	if strings.Contains(target, ":") && !strings.Contains(target, "[") {
		// check if it's a valid IP to avoid wrapping hostnames
		if ip := net.ParseIP(target); ip != nil && ip.To4() == nil {
			target = "[" + target + "]"
		}
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// 在 Dial 之前解析 IP，排除 DNS 时间
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ip, err := resolveIP(host)
			if err != nil {
				return nil, err
			}
			return net.DialTimeout(network, net.JoinHostPort(ip, port), timeout)
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
	start := time.Now()
	resp, err := client.Get(target)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return latency, nil
	}
	return latency, errors.New("http status not ok")
}

// ---- 同一探测目标的串行化与短时复用 ----

const (
	highLatencyThreshold     = 1000 // ms 阈值
	retryDropThresholdTcping = 800  // ms 重试中延迟降低超过此值则基本认为发生重传
	// 800ms = SYN/SYN-ACK 首次超时重传 1000ms - 防误判容许 200ms 延迟抖动
	pingMeasureWindow = 5 * time.Second
	// 不同目标之间的最小间隔。同一秒并发开多个 raw ICMP socket 时，
	// 回包会被别的协程抢先读走（实测 4 并发只收齐 3 个），
	// 原本正常的目标因此报「no packets received」。
	pingGap = time.Second
)

type pingMeasurement struct {
	latency int64
	err     error
	at      time.Time
}

var (
	pingMeasureMu sync.Mutex
	pingMeasures  = map[string]pingMeasurement{}
	pingKeyLocks  sync.Map // target key -> *sync.Mutex

	pingExecMu   sync.Mutex // 全局串行：同一时刻只跑一个测量
	pingLastDone time.Time  // 上一次测量结束时间（受 pingExecMu 保护）
)

func cachedMeasurement(key string) (int64, error, bool) {
	pingMeasureMu.Lock()
	defer pingMeasureMu.Unlock()
	if hit, ok := pingMeasures[key]; ok && time.Since(hit.at) < pingMeasureWindow {
		return hit.latency, hit.err, true
	}
	return 0, nil, false
}

func storeMeasurement(key string, latency int64, err error) {
	pingMeasureMu.Lock()
	defer pingMeasureMu.Unlock()
	now := time.Now()
	pingMeasures[key] = pingMeasurement{latency: latency, err: err, at: now}
	for k, v := range pingMeasures {
		if now.Sub(v.at) > time.Minute {
			delete(pingMeasures, k)
		}
	}
}

// measureForTarget 同一目标在窗口内复用结果，且不同目标之间串行、间隔 1 秒。
//
// 串行的原因不是目标限速，而是本机收包：探针通常跑在 VPC 内网（10.x），
// 出公网要走宿主 NAT。多个 raw ICMP socket 在同一毫秒发出、同一毫秒等待时，
// 宿主机做 SNAT 会话映射会发生状态覆盖，且回包到达后会向所有 raw socket 广播，
// 并发读的情况下有的协程拿到自己的、有的拿到别人的并被丢弃——表现出来就是
// 「延迟明明 168ms、却报 no packets received」。错开 1 秒后每个包独立完成
// 一次收发，丢包率才等于真实值。
func measureForTarget(pingType, target string, timeout time.Duration) (int64, error) {
	key := pingType + "|" + target

	if latency, err, ok := cachedMeasurement(key); ok {
		return latency, err
	}

	// 同一目标先串行，避免重复发包
	lock, _ := pingKeyLocks.LoadOrStore(key, &sync.Mutex{})
	mu := lock.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	if latency, err, ok := cachedMeasurement(key); ok {
		return latency, err
	}

	// 不同目标之间串行，且至少间隔 pingGap
	pingExecMu.Lock()
	defer pingExecMu.Unlock()

	// 排队期间可能已经有别的协程测完了同一目标
	if latency, err, ok := cachedMeasurement(key); ok {
		return latency, err
	}
	if !pingLastDone.IsZero() {
		if wait := pingGap - time.Since(pingLastDone); wait > 0 {
			time.Sleep(wait)
		}
	}

	latency, err := pingOnce(pingType, target, timeout)
	pingLastDone = time.Now()
	storeMeasurement(key, latency, err)
	return latency, err
}

// pingOnce 执行一次完整测量，含高延迟重试（与上游实现保持一致）。
func pingOnce(pingType, target string, timeout time.Duration) (int64, error) {
	measure := func() (int64, error) {
		switch pingType {
		case "icmp":
			return icmpPing(target, timeout)
		case "tcp":
			return tcpPing(target, timeout)
		case "http":
			return httpPing(target, timeout)
		default:
			return -1, errors.New("unsupported ping type")
		}
	}

	var latency int64
	var err error
	PingHighLatencyRetries := 3
	if latency, err = measure(); err == nil {
		firstLatency := latency
		if latency > int64(highLatencyThreshold) && PingHighLatencyRetries > 0 {
			attempts := PingHighLatencyRetries
			for i := 0; i < attempts; i++ {
				if second, err2 := measure(); err2 == nil {
					if second <= int64(highLatencyThreshold) {
						if pingType == "tcp" && firstLatency-second > int64(retryDropThresholdTcping) {
							err = errors.New("suspicious retransmission detected in tcp handshake")
							break
						}
						latency = second
						break
					}
					if i == attempts-1 { // 最后一次仍高
						err = errors.New("latency remains high after retries")
					}
				} else {
					err = err2
					break
				}
			}
		}
	}
	return latency, err
}

func NewPingTask(conn *ws.SafeConn, taskID uint, pingType, pingTarget string) {
	if taskID == 0 {
		log.Printf("Invalid task ID: %d", taskID)
		return
	}
	timeout := 3 * time.Second // 默认超时时间

	// 同一目标在窗口内只真正探测一次：多个监控任务指向同一个 IP 时，各自发一包
	// 会在同一秒叠加，目标侧 ICMP 限速只回其中一个，表现就是「一个任务 60% 丢包、
	// 另一个 0%」。复用结果既还原真实丢包率，也避免自己把自己打出限速。
	latency, err := measureForTarget(pingType, pingTarget, timeout)

	pingResult := -1
	if err != nil {
		// 带上目标，排查时能直接看出是哪个 IP 没回包
		log.Printf("Ping task %d (%s %s) failed: %v", taskID, pingType, pingTarget, err)
	} else {
		pingResult = int(latency)
	}
	finishedAt := time.Now()
	wsPayload := v2.BuildPingResultPayload(taskID, pingType, pingResult, finishedAt)
	// https://github.com/komari-monitor/komari/commit/eb87a4fc330b7d1c407fa4ff70177615a4f50a1f
	// -1 代表丢包，服务端计算
	//if pingResult == -1 {
	//	return
	//}
	if conn == nil {
		if err := postV2RPC(wsPayload); err != nil {
			log.Printf("Failed to upload ping result over POST: %v", err)
		}
		return
	}
	if err := conn.WriteJSON(wsPayload); err != nil {
		log.Printf("Failed to write JSON to WebSocket: %v", err)
	}

}

func postV2RPC(payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	endpoint := strings.TrimSuffix(flags.Endpoint, "/") + "/api/clients/v2/rpc?token=" + flags.Token
	compressed := false
	if !flags.DisableCompression {
		if gz, err := gzipBytes(body); err == nil {
			body = gz
			compressed = true
		}
	}
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if compressed {
		req.Header.Set("Content-Encoding", "gzip")
	}
	client := dnsresolver.GetHTTPClientWithPreference(30*time.Second, flags.PreferIPVersion)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return &httpStatusError{StatusCode: resp.StatusCode, Status: resp.Status, Body: string(respBody)}
	}
	if len(bytes.TrimSpace(respBody)) > 0 {
		if _, err := parseV2Response(respBody); err != nil {
			return err
		}
	}
	return nil
}

func gzipBytes(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
