package monitoring

// route.go —— 三网回程路由探测
//
// 服务器自己的 ASN 只代表机房供应商，跟「回国走什么线路」无关。
// 判断精品线路 / 普通骨干的唯一可靠办法：从本机向国内三网目标做 traceroute，
// 看回程路径上出现了哪些骨干节点前缀：
//
//	59.43.x.x   -> CN2 GIA（电信精品）
//	218.30.x.x  -> 9929（联通精品）
//	202.97.x.x  -> 163（电信普通骨干）
//	219.158.x.x -> 169（联通普通骨干）
//	223.120.x.x -> CMI（移动国际）
//
// 探测在后台异步执行并缓存（默认与线路判定同周期，24 小时），
// 不阻塞指标上报；系统没有 traceroute/mtr 时降级为「未知」。

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// RouteInfo 是单条回程线路的探测结果。
type RouteInfo struct {
	Carrier string `json:"carrier"` // 电信 / 联通 / 移动
	Target  string `json:"target"`  // 探测目标 IP
	Name    string `json:"name"`    // CN2 GIA / 9929 / 163 / 169 / CMI / 未知
	Tier    string `json:"tier"`    // premium(精品) / standard(普通) / unknown
	Hops    string `json:"hops"`    // 命中的关键节点（便于核对）
}

// routeTargets 是三网回程探测目标：各省会运营商的 DNS/接入点。
var routeTargets = []struct {
	carrier string
	target  string
}{
	{"电信", "202.96.209.133"},
	{"联通", "210.22.70.3"},
	{"移动", "211.136.192.6"},
}

// backboneRules 按优先级排列：越靠前越优先命中。
var backboneRules = []struct {
	prefix string
	name   string
	tier   string
}{
	// 顺序即「同一跳内」的匹配优先级；跨跳时以路径先后为准（先入境内地骨干者胜）
	{"59.43.", "CN2 GIA", "premium"},  // AS4809 电信 CN2 GIA
	{"218.105.", "9929", "premium"},   // AS9929 联通 CUII
	{"218.30.", "9929", "premium"},    // AS9929 国际段
	{"223.119.", "CMIN2", "premium"},  // AS58807 移动 CMIN2
	{"223.120.", "CMIN2", "premium"},  // AS58807 移动 CMIN2
	{"219.158.", "169", "standard"},   // AS4837 联通 169 骨干
	{"202.97.", "163", "standard"},    // AS4134 电信 163 骨干
	{"113.96.", "163", "standard"},    // AS4134 广东电信
	{"221.183.", "CMNET", "standard"}, // AS9808 移动 CMNET
	{"111.24.", "CMNET", "standard"},  // AS9808 移动 CMNET
	{"120.198.", "移动", "standard"},    // AS56040 广东移动
	{"211.136.", "移动", "standard"},    // AS56040 广东移动
	{"211.139.", "移动", "standard"},    // AS56040 广东移动
	{"210.14.", "联通", "standard"},     // CNC-BACKBONE 城域
}

// backboneSkip 是国际段前缀：看到它们说明还没进入内地骨干，继续看下一跳
var backboneSkip = []string{"162.219.", "43.255.", "203.160."}

var (
	routeCache    []RouteInfo
	routeCacheAt  time.Time
	routeCacheMu  sync.Mutex
	routeRunning  bool
	routeTTL      = 24 * time.Hour
	hopLineRe     = regexp.MustCompile(`^\s*(\d+)\s+([0-9a-fA-F:.]+)`)
	maxRouteHops  = "18"
	routeProbeTmo = 45 * time.Second
)

// SetRouteInterval 设置回程路由探测周期（<=0 忽略）。
func SetRouteInterval(d time.Duration) {
	if d <= 0 {
		return
	}
	routeCacheMu.Lock()
	routeTTL = d
	routeCacheMu.Unlock()
}

// GetRoutes 返回缓存的回程路由结果，必要时触发一次后台刷新。
// 首次调用返回空数组（探测在后台进行），不阻塞调用方。
func GetRoutes() []RouteInfo {
	routeCacheMu.Lock()
	cached := routeCache
	stale := time.Since(routeCacheAt) >= routeTTL || routeCacheAt.IsZero()
	start := stale && !routeRunning
	if start {
		routeRunning = true
	}
	routeCacheMu.Unlock()

	if start {
		go refreshRoutes()
	}
	if cached == nil {
		return []RouteInfo{}
	}
	return cached
}

func refreshRoutes() {
	results := make([]RouteInfo, 0, len(routeTargets))

	// 没有 traceroute/mtr 时直接给出明确结论，避免界面一直显示「探测中」
	if !hasTraceroute() {
		for _, t := range routeTargets {
			results = append(results, RouteInfo{
				Carrier: t.carrier, Target: t.target,
				Name: "未安装 traceroute", Tier: "unknown",
			})
		}
		routeCacheMu.Lock()
		routeCache = results
		routeCacheAt = time.Now()
		routeRunning = false
		routeCacheMu.Unlock()
		return
	}

	ch := make(chan RouteInfo, len(routeTargets))
	for _, t := range routeTargets {
		go func(carrier, target string) {
			ch <- probeRoute(carrier, target)
		}(t.carrier, t.target)
	}
	for i := 0; i < len(routeTargets); i++ {
		results = append(results, <-ch)
	}

	routeCacheMu.Lock()
	routeCache = results
	routeCacheAt = time.Now()
	routeRunning = false
	routeCacheMu.Unlock()
}

// probeRoute 对单个目标做 traceroute 并归类。
func probeRoute(carrier, target string) RouteInfo {
	info := RouteInfo{Carrier: carrier, Target: target, Name: "未知", Tier: "unknown"}

	hops, err := traceroute(target)
	if err != nil || len(hops) == 0 {
		return info
	}

	name, tier, hop := classifyHops(hops)
	info.Name, info.Tier = name, tier
	if hop != "" {
		info.Hops = hop
	} else if len(hops) > 0 {
		// 未命中已知骨干：记录最后一跳，界面上可据此核对确实探测过
		info.Hops = hops[len(hops)-1]
	}
	return info
}

// classifyHops 按「路径先后」判定：第一个进入内地骨干的节点决定线路类型。
// 这与 nexttrace 的 “-> ASxxxx” 语义一致，也符合回程测试的直观理解。
func classifyHops(hops []string) (name, tier, hop string) {
	for _, h := range hops {
		if isInternationalLeg(h) {
			continue
		}
		for _, rule := range backboneRules {
			if strings.HasPrefix(h, rule.prefix) {
				return rule.name, rule.tier, h
			}
		}
	}
	return "未知", "unknown", ""
}

func isInternationalLeg(ip string) bool {
	for _, p := range backboneSkip {
		if strings.HasPrefix(ip, p) {
			return true
		}
	}
	return false
}

// traceroute 依次尝试 traceroute 与 mtr，返回路径上的跳 IP。
func traceroute(target string) ([]string, error) {
	commands := [][]string{
		{"traceroute", "-n", "-m", maxRouteHops, "-q", "1", "-w", "2", target},
		{"traceroute", "-n", "-I", "-m", maxRouteHops, "-q", "1", "-w", "2", target},
		{"mtr", "-r", "-n", "-c", "1", "-m", maxRouteHops, target},
	}
	var lastErr error
	for _, argv := range commands {
		ctx, cancel := context.WithTimeout(context.Background(), routeProbeTmo)
		out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).Output()
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		if hops := parseHops(string(out)); len(hops) > 0 {
			return hops, nil
		}
		lastErr = nil
	}
	return nil, lastErr
}

// parseHops 从 traceroute/mtr 输出中提取跳 IP，忽略 * 与表头。
func parseHops(out string) []string {
	var hops []string
	for _, line := range strings.Split(out, "\n") {
		m := hopLineRe.FindStringSubmatch(line)
		if len(m) < 3 {
			continue
		}
		ip := m[2]
		if ip == "*" || strings.HasPrefix(ip, "*") {
			continue
		}
		hops = append(hops, ip)
	}
	return hops
}

// hasTraceroute 检查系统是否具备路由探测能力。
func hasTraceroute() bool {
	if _, err := exec.LookPath("traceroute"); err == nil {
		return true
	}
	if _, err := exec.LookPath("mtr"); err == nil {
		return true
	}
	return false
}
