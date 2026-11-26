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
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RouteInfo 是单条回程线路的探测结果。
type RouteInfo struct {
	TaskID  uint   `json:"task_id,omitempty"` // 对应后台监控任务 ID
	Carrier string `json:"carrier"`           // 电信 / 联通 / 移动
	Target  string `json:"target"`            // 探测目标 IP
	Name    string `json:"name"`              // CN2 GIA / 9929 / 163 / 169 / CMI / 未知
	Tier    string `json:"tier"`              // premium(精品) / standard(普通) / unknown
	Hops    string `json:"hops"`              // 命中的关键节点（便于核对）
}

// defaultRouteTargets 仅在还没收到任何监控任务时用于兜底探测。
var defaultRouteTargets = []routeTarget{
	{taskID: 0, carrier: "电信", host: "202.96.209.133", typ: "icmp"},
	{taskID: 0, carrier: "联通", host: "210.22.70.3", typ: "icmp"},
	{taskID: 0, carrier: "移动", host: "211.136.192.6", typ: "icmp"},
}

type routeTarget struct {
	taskID  uint
	carrier string
	host    string
	port    int
	typ     string // icmp / tcp / udp，决定用哪种探测方式
}

// monitoredTargets 保存后台下发的监控目标（taskID -> 目标 IP），
// 回程探测优先使用这些目标，保证「测的就是你在监控的那条线」。
var (
	monitoredMu      sync.RWMutex
	monitoredTargets = map[uint]routeTarget{}
	monitoredOrder   []uint
)

// SetRouteTarget 记录一个后台监控任务的目标（由 agent.ping 事件带入）。
// target 可能是 1.2.3.4、host、host:80 甚至 [v6]:443，这里统一拆成 host + port。
func SetRouteTarget(taskID uint, target, pingType string) {
	// 先恢复落盘的探测结果，让重启后的首屏不至于空白。
	// 注意：loadRouteState 只恢复结果、不恢复探测时间，本进程仍会重新检测一次。
	routeStateOnce.Do(loadRouteState)
	host, port := splitHostPort(target)
	if taskID == 0 || host == "" {
		return
	}
	next := routeTarget{
		taskID: taskID, host: host, port: port, typ: strings.ToLower(pingType),
	}

	monitoredMu.Lock()
	prev, existed := monitoredTargets[taskID]
	monitoredTargets[taskID] = next
	if !existed {
		monitoredOrder = append(monitoredOrder, taskID)
		// 目标过多会拖长探测时间，只保留最近写入的若干个
		const maxMonitoredTargets = 6
		if len(monitoredOrder) > maxMonitoredTargets {
			drop := monitoredOrder[0]
			delete(monitoredTargets, drop)
			monitoredOrder = monitoredOrder[1:]
		}
	}
	monitoredMu.Unlock()

	// 只有地址/端口/类型真的变了才重测；单纯重复下发（每轮 ping 都会带）不触发。
	// 重启后 monitoredTargets 为空，重新登记同一批目标会走 !existed 分支并安排一次
	// 重新检测——这是明确要求的功能（重启即重测），不能跳过。
	if !existed || prev.host != next.host || prev.port != next.port || prev.typ != next.typ {
		scheduleRouteRefresh()
	}
}

// currentRouteTargets 返回本轮要探测的目标：优先用后台监控目标。
func currentRouteTargets() []routeTarget {
	monitoredMu.RLock()
	defer monitoredMu.RUnlock()
	if len(monitoredOrder) == 0 {
		return defaultRouteTargets
	}
	out := make([]routeTarget, 0, len(monitoredOrder))
	for _, id := range monitoredOrder {
		if t, ok := monitoredTargets[id]; ok && t.host != "" {
			out = append(out, t)
		}
	}
	return out
}

// backboneRules 按优先级排列：越靠前越优先命中。
var backboneRules = []struct {
	prefix string
	name   string
	tier   string
}{
	// 只保留「产品级」线路名；城域节点（210.14/211.136 等）不算线路，
	// 命中不了就显示「未知」并在 tooltip 里给出末跳，避免把城市骨干误标成线路。
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

	// 目标变化后的去抖与最小间隔：避免一条条下发任务时连续重测
	routeDirty    bool
	routeTimer    *time.Timer
	routeDebounce = 90 * time.Second
	routeMinGap   = 10 * time.Minute

	// routesUpdatedHook 在每轮回程探测完成后触发，用于把最新结果上报给面板。
	routesUpdatedHook func()
)

// routeStateVersion 标识缓存格式；旧版本缓存（可能含运营商名 / ASN 等
// 非线路名的脏数据）一律丢弃，等本进程重新探测后再落盘。
const routeStateVersion = 2

// routeState 是落盘的探测结果，保证重启后首屏不至于空白。
type routeState struct {
	Version  int         `json:"version"`
	ProbedAt time.Time   `json:"probed_at"`
	Results  []RouteInfo `json:"results"`
}

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
var routeStateOnce sync.Once

func GetRoutes() []RouteInfo {
	routeStateOnce.Do(loadRouteState)
	routeCacheMu.Lock()
	cached := routeCache
	// routeCacheAt 为零表示「本进程尚未探测」：重启后必须重新检测一次。
	stale := routeCacheAt.IsZero() || time.Since(routeCacheAt) >= routeTTL
	running := routeRunning
	routeCacheMu.Unlock()

	if stale && !running {
		// 统一走去抖调度，等后台监控目标都登记完再测，
		// 避免重启瞬间目标还没下发时用内置默认地址多测一轮。
		scheduleRouteRefresh()
	}
	if cached == nil {
		return []RouteInfo{}
	}
	return cached
}

func refreshRoutes() {
	defer func() {
		routeCacheMu.Lock()
		routeDirty = false
		hook := routesUpdatedHook
		routeCacheMu.Unlock()
		// 探测结果落盘后主动刷新 basicInfo，避免面板一直显示启动时的旧快照
		if hook != nil {
			go hook()
		}
	}()
	targets := currentRouteTargets()
	results := make([]RouteInfo, 0, len(targets))

	// 没有 traceroute/mtr 时直接给出明确结论，避免界面一直显示「探测中」
	if !hasTraceroute() {
		for _, t := range targets {
			results = append(results, RouteInfo{
				TaskID: t.taskID, Carrier: t.carrier, Target: t.host,
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

	ch := make(chan RouteInfo, len(targets))
	for _, t := range targets {
		go func(t routeTarget) {
			info := probeRoute(t.carrier, t.host, t.port, t.typ)
			info.TaskID = t.taskID
			ch <- info
		}(t)
	}
	for i := 0; i < len(targets); i++ {
		results = append(results, <-ch)
	}

	routeCacheMu.Lock()
	routeCache = results
	routeCacheAt = time.Now()
	routeRunning = false
	routeCacheMu.Unlock()
	saveRouteState()
}

// probeRoute 对单个目标做 traceroute 并归类。
func probeRoute(carrier, host string, port int, pingType string) RouteInfo {
	info := RouteInfo{Carrier: carrier, Target: host, Name: "未知", Tier: "unknown"}

	// TCP/UDP 监控目标：对端多半只开放该端口，用 TCP SYN 探测才有回包
	tcp := (pingType == "tcp" || pingType == "udp") && port > 0
	hops, err := traceroute(host, port, tcp)
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
func traceroute(target string, port int, tcp bool) ([]string, error) {
	commands := make([][]string, 0, 4)
	if tcp && port > 0 {
		commands = append(commands, []string{
			"traceroute", "-n", "-T", "-p", strconv.Itoa(port),
			"-m", maxRouteHops, "-q", "1", "-w", "2", target,
		})
	}
	commands = append(commands,
		[]string{"traceroute", "-n", "-m", maxRouteHops, "-q", "1", "-w", "2", target},
		[]string{"traceroute", "-n", "-I", "-m", maxRouteHops, "-q", "1", "-w", "2", target},
		[]string{"mtr", "-r", "-n", "-c", "1", "-m", maxRouteHops, target},
	)
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

// splitHostPort 从监控目标里拆出主机与端口。
// 支持 1.2.3.4、example.com、example.com:80、[2400::1]:443。
func splitHostPort(raw string) (string, int) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0
	}
	host, portStr, err := net.SplitHostPort(raw)
	if err == nil {
		port, _ := strconv.Atoi(portStr)
		return host, port
	}
	return raw, 0
}

// SetRoutesUpdatedHook 注册每轮回程探测完成后的回调。
// 由 server 包用于重新上报 basicInfo，让面板及时拿到最新线路结果。
func SetRoutesUpdatedHook(fn func()) {
	routeCacheMu.Lock()
	routesUpdatedHook = fn
	routeCacheMu.Unlock()
}

// scheduleRouteRefresh 在目标变化后安排一次去抖刷新。
func scheduleRouteRefresh() {
	routeCacheMu.Lock()
	routeDirty = true
	if routeTimer == nil {
		routeTimer = time.AfterFunc(routeDebounce, func() {
			routeCacheMu.Lock()
			routeTimer = nil
			dirty := routeDirty
			last := routeCacheAt
			running := routeRunning
			routeCacheMu.Unlock()

			if !dirty || running {
				return
			}
			// 距上次探测太近就跳过，等下一个 24 小时周期
			if !last.IsZero() && time.Since(last) < routeMinGap {
				return
			}
			refreshRoutes()
		})
	}
	routeCacheMu.Unlock()
}

func routeStatePath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "route-cache.json")
}

func loadRouteState() {
	p := routeStatePath()
	if p == "" {
		return
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var st routeState
	if err := json.Unmarshal(data, &st); err != nil || len(st.Results) == 0 {
		return
	}
	// 旧格式缓存里可能混有运营商名 / ASN 之类的无效线路名，直接丢弃
	if st.Version != routeStateVersion {
		return
	}
	if time.Since(st.ProbedAt) >= routeTTL {
		return
	}
	routeCacheMu.Lock()
	routeCache = st.Results
	// 只恢复结果供首屏显示，刻意不恢复 routeCacheAt：
	// 重启后按需求必须重新检测一次，本进程仍视为「尚未探测」。
	routeCacheMu.Unlock()
}

func saveRouteState() {
	p := routeStatePath()
	if p == "" {
		return
	}
	routeCacheMu.Lock()
	st := routeState{Version: routeStateVersion, ProbedAt: routeCacheAt, Results: routeCache}
	routeCacheMu.Unlock()
	data, err := json.Marshal(st)
	if err != nil {
		return
	}
	_ = os.WriteFile(p, data, 0o644)
}
