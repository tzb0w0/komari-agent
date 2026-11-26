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
	"fmt"
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
	TaskID   uint   `json:"task_id,omitempty"`  // 对应后台监控任务 ID
	Carrier  string `json:"carrier"`            // 目标运营商（后台任务名推断）：电信 / 联通 / 移动
	Target   string `json:"target"`             // 探测目标 IP
	Name     string `json:"name"`               // CN2 GIA / CN2 GT / 9929 / CMIN2 / 169 / CMI / 163 / CMNET / 未知
	Tier     string `json:"tier"`               // premium(精品) / standard(普通) / unknown
	Backbone string `json:"backbone,omitempty"` // 骨干网归属：电信 / 联通 / 移动
	Cross    bool   `json:"cross,omitempty"`    // 目标运营商与骨干归属不一致（仅供数据侧参考，界面不显示）
	Hops     string `json:"hops"`               // 命中的关键节点（便于核对）
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
// taskName 是后台填写的任务名（如「广东电信」），用于判断目的运营商：
// 同样的路径前缀，对电信目标和对联通目标代表的线路完全不同。
func SetRouteTarget(taskID uint, taskName, target, pingType string) {
	// 先恢复落盘的探测结果，让重启后的首屏不至于空白。
	// 注意：loadRouteState 只恢复结果、不恢复探测时间，本进程仍会重新检测一次。
	routeStateOnce.Do(loadRouteState)
	host, port := splitHostPort(target)
	if taskID == 0 || host == "" {
		return
	}
	next := routeTarget{
		taskID: taskID, carrier: carrierFromName(taskName),
		host: host, port: port, typ: strings.ToLower(pingType),
	}

	monitoredMu.Lock()
	prev, existed := monitoredTargets[taskID]
	monitoredTargets[taskID] = next
	if !existed {
		monitoredOrder = append(monitoredOrder, taskID)
		// 目标过多会拖长探测时间，只保留最近写入的若干个
		const maxMonitoredTargets = 12
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

// carrierFromName 从后台任务名里推断目的运营商，识别不出时返回空串，
// 此时判定退化为「路径上第一个骨干节点」。
func carrierFromName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch {
	case hasAny(n, "电信", "telecom", "ctcc", "chinanet"):
		return "电信"
	case hasAny(n, "联通", "unicom", "cucc", "china169"):
		return "联通"
	case hasAny(n, "移动", "mobile", "cmcc"):
		return "移动"
	}
	return ""
}

func hasAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
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

// routeFeature 描述一条骨干线路的识别特征与展示信息。
//
// 判定不看「落地 AS」，因为跨境路径的落地跳经常属于目标运营商自己的
// ChinaNet / CMNET 网（AS4134 / AS9808），纯粹的 CN2 路径会被判成 163。
// 这里改为「骨干网特征优先级匹配」：先看路径里出现了哪张骨干网，
// 再按优先级取第一条命中——这才是回程线路的通行口径。
type routeFeature struct {
	name    string   // 面板徽章显示的线路名（界面只展示这一个值）
	tier    string   // premium / standard / unknown
	carrier string   // 骨干网归属运营商
	prefix  []string // IP 前缀特征
	asn     []int    // ASN 特征
}

var (
	// 规则 1 / 4：59.43 / AS4809 是 CN2，核心段是否混有 202.97 决定 GIA 还是 GT
	featCN2GIA = routeFeature{"CN2 GIA", "premium", "电信", []string{"59.43."}, []int{4809}}
	featCN2GT  = routeFeature{"CN2 GT", "standard", "电信", []string{"59.43."}, []int{4809}}

	// 规则 2：联通 CUII。218.105 / 210.51 是 AS9929 的强特征；
	// 210.14 只是联通城域骨干（169 路径也会经过），单独出现时降级为弱证据。
	feat9929Strong = routeFeature{"9929", "premium", "联通", []string{"218.105.", "210.51."}, []int{9929}}
	feat9929       = routeFeature{"9929", "premium", "联通", []string{"218.105.", "210.51.", "210.14."}, []int{9929}}

	// 规则 3：移动 CMIN2
	featCMIN2 = routeFeature{"CMIN2", "premium", "移动", []string{"223.120."}, []int{58807}}

	// 规则 5：联通 169
	feat169 = routeFeature{"169", "standard", "联通", []string{"219.158."}, []int{4837}}

	// 规则 6：移动 CMI 普通国际出口
	featCMI = routeFeature{"CMI", "standard", "移动", []string{"223.118.", "223.119."}, []int{58453}}

	// 规则 7：电信 163
	feat163 = routeFeature{"163", "standard", "电信", []string{"202.97.", "218.30.", "113.96."}, []int{4134}}

	// 规则 8（规则表外的兜底）：移动 CMNET 国内骨干，
	// 不加这条则普通移动回程会全部变「未知」，信息量反而下降。
	featCMNET = routeFeature{"CMNET", "standard", "移动", []string{"221.176.", "221.183.", "111.24."}, []int{9808}}
)

// backboneSkip 是纯国际段前缀（联通 CUG、电信 CTG 等），不代表回国线路，
// 只在没有 ASN 信息时用于跳过境外跳。
var backboneSkip = []string{"162.219.", "43.255.", "203.160."}

var (
	routeCache   []RouteInfo
	routeCacheAt time.Time
	routeCacheMu sync.Mutex
	routeRunning bool
	routeTTL     = 24 * time.Hour
	hopLineRe    = regexp.MustCompile(`^\s*(\d+)\s+([0-9a-fA-F:.]+)`)
	// mtr -r -n 的行格式是 ` 1.|-- 1.2.3.4 ...`，与 traceroute 不同
	mtrLineRe     = regexp.MustCompile(`^\s*(\d+)\.\|--\s+([0-9a-fA-F:.]+)`)
	maxRouteHops  = "20"
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
const routeStateVersion = 6

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

	c := classifyRoute(hops)
	info.Name, info.Tier = c.name, c.tier
	info.Backbone = c.carrier
	info.Cross = carrier != "" && c.carrier != "" && carrier != c.carrier
	// 把「命中跳及其前几跳」一起上报，面板 tooltip 直接可见，
	// 出现偏差时用户不用猜、也不需要再跑 nq 就能核对
	info.Hops = pathSummary(hops, c.hop)
	return info
}

// pathSummary 生成用于人工核对的路径片段：落地跳 + 它前面最多 3 跳。
func pathSummary(hops []string, matched string) string {
	if len(hops) == 0 {
		return ""
	}
	idx := len(hops) - 1
	if matched != "" {
		for i, h := range hops {
			if h == matched {
				idx = i
				break
			}
		}
	}
	start := idx - 3
	if start < 0 {
		start = 0
	}
	parts := append([]string{}, hops[start:idx+1]...)
	if matched != "" {
		if asn, cc, found := originASNCached(matched); found {
			parts[len(parts)-1] += fmt.Sprintf("(AS%d/%s)", asn, cc)
		}
	}
	return fmt.Sprintf("%s（第%d跳/共%d跳）",
		strings.Join(parts, " → "), idx+1, len(hops))
}

// ---- 跨境落地跳的 ASN / 国家判定 ----
//
// 通过 Team Cymru 的 DNS 接口查每个跳的 ASN 与注册国家：
//
//	<reversed-ip>.origin.asn.cymru.com  TXT -> "4134 | 218.30.0.0/16 | CN | apnic | 2002-03-15"
//
// 第一个 cc=="CN" 的跳就是「跨境落地那一跳」，其 ASN 决定线路。
// 查询失败会熔断（asnOff），整块退回前缀表，不会因为 DNS 不通而卡死或变未知。
var (
	asnCacheMu sync.Mutex
	asnCache   = map[string]asnInfo{}
	asnFails   int
	asnOff     bool

	// originASN 可在测试中替换
	originASN = lookupOriginASN
)

type asnInfo struct {
	asn int
	cc  string
	ok  bool
}

func originASNCached(ip string) (int, string, bool) {
	// 私有/保留地址（192.168.x、10.x、链路本地等）不可能有 ASN，
	// 直接跳过，且不计入失败次数——否则开头几个内网跳就会把熔断打满。
	if parsed := net.ParseIP(ip); parsed == nil || isNonRoutable(parsed) {
		return 0, "", false
	}

	asnCacheMu.Lock()
	if v, hit := asnCache[ip]; hit {
		asnCacheMu.Unlock()
		return v.asn, v.cc, v.ok
	}
	off := asnOff
	asnCacheMu.Unlock()
	if off {
		return 0, "", false
	}

	asn, cc := originASN(ip)

	asnCacheMu.Lock()
	defer asnCacheMu.Unlock()
	if asn == 0 {
		asnFails++
		if asnFails >= 4 {
			asnOff = true
		}
	} else {
		asnFails = 0
	}
	asnCache[ip] = asnInfo{asn: asn, cc: cc, ok: asn != 0}
	return asn, cc, asn != 0
}

func isNonRoutable(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

func lookupOriginASN(ip string) (int, string) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0, ""
	}
	var q string
	if v4 := parsed.To4(); v4 != nil {
		q = fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0])
	} else {
		b := parsed.To16()
		if b == nil {
			return 0, ""
		}
		const hexDigits = "0123456789abcdef"
		var sb strings.Builder
		for i := len(b) - 1; i >= 0; i-- {
			sb.WriteByte(hexDigits[b[i]&0x0f])
			sb.WriteByte('.')
			sb.WriteByte(hexDigits[b[i]>>4])
			sb.WriteByte('.')
		}
		q = sb.String() + "origin6.asn.cymru.com"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	txts, err := net.DefaultResolver.LookupTXT(ctx, q)
	if err != nil || len(txts) == 0 {
		return 0, ""
	}
	fields := strings.Split(txts[0], "|")
	if len(fields) < 3 {
		return 0, ""
	}
	asnStr := strings.TrimSpace(fields[0])
	if i := strings.IndexByte(asnStr, ' '); i > 0 {
		asnStr = asnStr[:i]
	}
	asn, err := strconv.Atoi(asnStr)
	if err != nil || asn == 0 {
		return 0, ""
	}
	return asn, strings.ToUpper(strings.TrimSpace(fields[2]))
}

// routeClass 是单条目标的判定结果。
type routeClass struct {
	name, tier, carrier, hop string
	matched                  bool
}

// hopFacts 是单跳的 ASN / 国家信息。
type hopFacts struct {
	ip     string
	asn    int
	cc     string
	hasASN bool
}

func (f routeFeature) match(h hopFacts) bool {
	for _, p := range f.prefix {
		if strings.HasPrefix(h.ip, p) {
			return true
		}
	}
	if h.hasASN {
		for _, a := range f.asn {
			if h.asn == a {
				return true
			}
		}
	}
	return false
}

// collectHopFacts 逐跳查 ASN（有缓存，重复探测不会重复查询）。
func collectHopFacts(hops []string) []hopFacts {
	limit := len(hops)
	if limit > 20 {
		limit = 20 // 落地跳不会太靠后，限制 DNS 查询次数
	}
	out := make([]hopFacts, 0, limit)
	for _, ip := range hops[:limit] {
		h := hopFacts{ip: ip}
		if asn, cc, ok := originASNCached(ip); ok {
			h.asn, h.cc, h.hasASN = asn, cc, true
		}
		out = append(out, h)
	}
	return out
}

// coreStart 定位「核心段」起点：第一个位于中国大陆的跳。
// 拿不到 ASN（DNS 不通）时退回到第一个命中骨干特征的跳，避免核心段判空。
func coreStart(facts []hopFacts) int {
	for i, h := range facts {
		if h.hasASN && h.cc == "CN" {
			return i
		}
	}
	all := []routeFeature{featCN2GIA, feat9929, featCMIN2, feat169, featCMI, feat163, featCMNET}
	for i, h := range facts {
		if isInternationalLeg(h.ip) {
			continue
		}
		for _, f := range all {
			if f.match(h) {
				return i
			}
		}
	}
	return 0
}

// coreHas163Backbone 判断核心段是否混有 202.97（163 骨干网）。
// 只认 202.97 前缀：AS4134 还包含 113.96 等省级段，CN2 GIA 落地后同样会
// 经过 AS4134，用 ASN 判断会把纯 GIA 误标成 GT。
func coreHas163Backbone(core []hopFacts) bool {
	for _, h := range core {
		if strings.HasPrefix(h.ip, "202.97.") {
			return true
		}
	}
	return false
}

func firstHit(f routeFeature, facts []hopFacts) (bool, string) {
	for _, h := range facts {
		if f.match(h) {
			return true, h.ip
		}
	}
	return false, ""
}

func firstHitPrefix(facts []hopFacts, prefix string) (bool, string) {
	for _, h := range facts {
		if strings.HasPrefix(h.ip, prefix) {
			return true, h.ip
		}
	}
	return false, ""
}

func pick(f routeFeature, hop string) routeClass {
	return routeClass{name: f.name, tier: f.tier, carrier: f.carrier, hop: hop, matched: true}
}

// classifyRoute 按「骨干网特征优先级」判定回程线路，顺序与需求口径一致：
//
//  1. 59.43 / AS4809，且核心段无 202.97   → CN2 GIA 优质
//  2. 218.105 / 210.51 / 210.14 / AS9929 → 9929 优质
//  3. 223.120 / AS58807                  → CMIN2 优质
//  4. 59.43 / AS4809，核心段混有 202.97   → CN2 GT 半程优化
//  5. 219.158 / AS4837                   → 169 普通
//  6. 223.118 / 223.119 / AS58453        → CMI 普通
//  7. 202.97 / AS4134                    → 163 普通
//  8. 221.176 / 221.183 / 111.24 / AS9808 → CMNET 普通（兜底）
//
// 判定与目标运营商无关：电信目标回程走 9929 就判 9929，联通目标走
// CN2 就判 CN2，跨网由 buildRouteLabel 标注，不强行归到本网。
func classifyRoute(hops []string) routeClass {
	if len(hops) == 0 {
		return routeClass{name: "未知", tier: "unknown"}
	}
	facts := collectHopFacts(hops)
	core := facts[coreStart(facts):]

	// 规则 1 / 4：CN2。命中 59.43 后看核心段是否混有 202.97 区分 GIA / GT。
	if ok, hop := firstHit(featCN2GIA, facts); ok {
		if coreHas163Backbone(core) {
			return pick(featCN2GT, hop)
		}
		return pick(featCN2GIA, hop)
	}

	// 规则 2：9929。强特征优先；210.14 单独出现时，只有在同路径没有
	// 219.158（169 骨干）的情况下才认作 9929，否则会把握手走 169 的线路误标成精品。
	if ok, hop := firstHit(feat9929Strong, facts); ok {
		return pick(feat9929, hop)
	}
	if ok, hop := firstHitPrefix(facts, "210.14."); ok {
		if has169, _ := firstHit(feat169, facts); !has169 {
			return pick(feat9929, hop)
		}
	}

	// 规则 3
	if ok, hop := firstHit(featCMIN2, facts); ok {
		return pick(featCMIN2, hop)
	}
	// 规则 5
	if ok, hop := firstHit(feat169, facts); ok {
		return pick(feat169, hop)
	}
	// 规则 6
	if ok, hop := firstHit(featCMI, facts); ok {
		return pick(featCMI, hop)
	}
	// 规则 7
	if ok, hop := firstHit(feat163, facts); ok {
		return pick(feat163, hop)
	}
	// 规则 8（兜底）
	if ok, hop := firstHit(featCMNET, facts); ok {
		return pick(featCMNET, hop)
	}
	return routeClass{name: "未知", tier: "unknown"}
}

// classifyHops 保留旧签名，供测试与调用方使用。
func classifyHops(hops []string) (name, tier, hop string) {
	c := classifyRoute(hops)
	return c.name, c.tier, c.hop
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
			"-m", maxRouteHops, "-q", "3", "-w", "3", target,
		})
	}
	commands = append(commands,
		[]string{"traceroute", "-n", "-m", maxRouteHops, "-q", "3", "-w", "3", target},
		[]string{"traceroute", "-n", "-I", "-m", maxRouteHops, "-q", "3", "-w", "3", target},
		[]string{"mtr", "-r", "-n", "-c", "2", "-m", maxRouteHops, target},
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
			m = mtrLineRe.FindStringSubmatch(line)
		}
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
