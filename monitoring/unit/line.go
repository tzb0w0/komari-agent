package monitoring

// line.go —— 出口线路自动识别
//
// 原理：探针运行在被监控服务器上，能拿到这台机器访问公网的"出口 IP"。
// 通过多个 CDN 的 /cdn-cgi/trace 端点读取出口 IP，再查询该 IP 的 ASN，
// 按 ASN 规则判定当前线路（CN2 GIA / 9929 / 4837 / CMIN / 163 等）。
// 结果随 basicInfo 上报到面板，前端据此显示当前线路——全程自动，无需手填。

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// lineRule 定义 ASN -> 线路 的映射规则。顺序即优先级。
var lineRules = []struct {
	id      string
	name    string
	carrier string
	asns    []int
}{
	{"cn2gia", "CN2 GIA", "电信", []int{4809, 4812, 4816}},
	{"9929", "9929", "联通", []int{9929}},
	{"4837", "4837", "联通", []int{4837}},
	{"cmin", "CMIN", "移动", []int{58807, 9808}},
	{"163", "163", "电信", []int{4134}},
}

// LineInfo 是上报给面板的线路信息。
type LineInfo struct {
	Name    string `json:"name"`    // 线路名，如 CN2 GIA
	ID      string `json:"id"`      // 线路标识，如 cn2gia
	Carrier string `json:"carrier"` // 运营商
	ASN     int    `json:"asn"`     // 识别到的自治域号
	IP      string `json:"ip"`      // 出口 IP
	Source  string `json:"source"`  // 识别来源，固定 "auto"
}

var (
	lineCache   LineInfo
	lineCacheAt time.Time
	lineCacheMu sync.Mutex
	// lineCacheTTL 是线路识别结果的缓存时长，默认 24 小时，可由面板配置下发覆盖。
	lineCacheTTL = 24 * time.Hour
)

// SetLineDetectInterval 设置线路重新判定间隔（<=0 时忽略）。
func SetLineDetectInterval(d time.Duration) {
	if d <= 0 {
		return
	}
	lineCacheMu.Lock()
	lineCacheTTL = d
	lineCacheMu.Unlock()
}

// traceEndpoints 返回出口 IP 的端点。这些端点会回显访问者的 IP。
var traceEndpoints = []string{
	"https://www.visa.cn/cdn-cgi/trace",
	"https://www.qualcomm.cn/cdn-cgi/trace",
	"https://cloudflare.com/cdn-cgi/trace",
	"https://ipv4.ip.sb",
}

var ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
var asnRe = regexp.MustCompile(`(?:AS|as)\s*(\d+)`)

// DetectLine 自动识别当前出口线路，默认缓存 24 小时（可由面板配置）。
func DetectLine() LineInfo {
	lineCacheMu.Lock()
	defer lineCacheMu.Unlock()
	if lineCache.ID != "" && time.Since(lineCacheAt) < lineCacheTTL {
		return lineCache
	}

	ip := detectExitIP()
	info := LineInfo{Source: "auto", IP: ip}
	if ip == "" {
		info.Name = "未识别"
		info.ID = "unknown"
		lineCache = info
		lineCacheAt = time.Now()
		return info
	}

	asn := queryASN(ip)
	info.ASN = asn
	if rule := matchLineByASN(asn); rule != nil {
		info.Name = rule.name
		info.ID = rule.id
		info.Carrier = rule.carrier
	} else {
		info.Name = "AS" + strconv.Itoa(asn)
		info.ID = "other"
		info.Carrier = "未知"
	}
	if asn == 0 {
		info.Name = "未识别"
		info.ID = "unknown"
	}

	lineCache = info
	lineCacheAt = time.Now()
	return info
}

// matchLineByASN 按 ASN 匹配线路规则，供本包与测试复用。
func matchLineByASN(asn int) *struct {
	id      string
	name    string
	carrier string
	asns    []int
} {
	if asn <= 0 {
		return nil
	}
	for i := range lineRules {
		for _, a := range lineRules[i].asns {
			if a == asn {
				return &lineRules[i]
			}
		}
	}
	return nil
}

// detectExitIP 从 CDN trace 端点读取出口 IPv4。
func detectExitIP() string {
	client := &http.Client{Timeout: 6 * time.Second}
	for _, endpoint := range traceEndpoints {
		req, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "curl/8.0.1")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		if err != nil {
			continue
		}
		text := string(body)
		// /cdn-cgi/trace 里有 ip= 字段，优先取它
		scanner := bufio.NewScanner(strings.NewReader(text))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "ip=") {
				ip := strings.TrimSpace(strings.TrimPrefix(line, "ip="))
				if ipv4Re.MatchString(ip) {
					return ip
				}
			}
		}
		if ip := ipv4Re.FindString(text); ip != "" {
			return ip
		}
	}
	return ""
}

// queryASN 通过公开 ASN 查询服务获取 IP 所属 ASN。
func queryASN(ip string) int {
	endpoints := []string{
		"https://ipinfo.io/" + ip + "/json",
		"https://api.ip.sb/geoip?ip=" + ip,
	}
	client := &http.Client{Timeout: 6 * time.Second}
	for _, endpoint := range endpoints {
		req, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "curl/8.0.1")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		if err != nil {
			continue
		}
		// ipinfo.io 返回 {"org":"AS4809 China Telecom", ...}
		var obj map[string]interface{}
		if json.Unmarshal(body, &obj) == nil {
			for _, key := range []string{"asn", "org"} {
				if v, ok := obj[key]; ok {
					if s, ok := v.(string); ok {
						if m := asnRe.FindStringSubmatch(s); len(m) == 2 {
							if n, err := strconv.Atoi(m[1]); err == nil {
								return n
							}
						}
					}
				}
			}
		}
		// 纯文本也尝试匹配
		if m := asnRe.FindStringSubmatch(string(body)); len(m) == 2 {
			if n, err := strconv.Atoi(m[1]); err == nil {
				return n
			}
		}
	}
	return 0
}

// DescribeLine 返回可读描述，便于日志输出。
func DescribeLine(info LineInfo) string {
	if info.ASN > 0 {
		return fmt.Sprintf("%s (AS%d, %s)", info.Name, info.ASN, info.IP)
	}
	return fmt.Sprintf("%s (%s)", info.Name, info.IP)
}
