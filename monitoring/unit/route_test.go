package monitoring

import "testing"

// testASNTable 模拟 Team Cymru 的查询结果。
// 用例取自用户实测的 nq 输出（广东电信 / 广东联通 / 广东移动）。
var testASNTable = map[string][2]interface{}{
	"199.102.1.1": {402506, "US"},
	"218.30.54.1": {4134, "CN"},  // 上海 CHINANET-US（电信落地，但仍属 AS4134）
	"59.43.246.1": {4809, "CN"},  // CN2 广州
	"59.43.130.1": {4809, "CN"},  // CN2 骨干
	"202.97.12.1": {4134, "CN"},  // 163 广州
	"113.96.1.1":  {4134, "CN"},  // 广东电信
	"162.219.1.1": {10099, "US"}, // CUG 洛杉矶
	"43.255.1.1":  {10099, "HK"}, // CUG 香港
	"218.105.2.1": {9929, "CN"},  // CUII 广州
	"219.158.1.1": {4837, "CN"},  // 169 广州
	"223.120.1.1": {58807, "US"}, // CMIN2 洛杉矶
	"223.120.2.1": {58807, "CN"}, // CMIN2 上海
	"223.118.1.1": {58453, "CN"}, // CMI
	"221.183.1.1": {9808, "CN"},  // CMNET
	"210.14.1.1":  {0, "CN"},     // 城域节点，无 ASN
}

func setASNResolver(t *testing.T, fn func(string) (int, string)) {
	t.Helper()
	restore := originASN
	originASN = fn
	asnCacheMu.Lock()
	asnCache = map[string]asnInfo{}
	asnFails, asnOff = 0, false
	asnCacheMu.Unlock()
	t.Cleanup(func() {
		originASN = restore
		asnCacheMu.Lock()
		asnCache = map[string]asnInfo{}
		asnFails, asnOff = 0, false
		asnCacheMu.Unlock()
	})
}

// 判定口径：按「骨干网特征优先级」匹配，不看落地 AS 归属。
// 这样 CN2 路径不会因为落地跳属 AS4134 被误判成 163。
func TestClassifyHops(t *testing.T) {
	setASNResolver(t, func(ip string) (int, string) {
		if v, ok := testASNTable[ip]; ok {
			return v[0].(int), v[1].(string)
		}
		return 0, ""
	})

	cases := []struct {
		desc      string
		target    string
		hops      []string
		wantName  string
		wantTier  string
		wantHop   string
		wantCross bool
	}{
		{
			// 用户实测：218.30(AS4134) → 59.43(CN2) → 202.97(163 骨干) → 113.96
			// 有 59.43 但核心段混有 202.97 → CN2 GT（半程优化），不是 163、也不是 GIA
			desc:     "广东电信实测路径：59.43 + 202.97 → CN2 GT",
			target:   "电信",
			hops:     []string{"199.102.1.1", "218.30.54.1", "59.43.246.1", "202.97.12.1", "113.96.1.1"},
			wantName: "CN2 GT", wantTier: "standard", wantHop: "59.43.246.1",
			wantCross: false,
		},
		{
			// 纯 CN2 GIA：全程 59.43，核心段没有 202.97
			desc:     "CN2 GIA：59.43 且核心段无 202.97",
			target:   "电信",
			hops:     []string{"199.102.1.1", "218.30.54.1", "59.43.246.1", "59.43.130.1", "113.96.1.1"},
			wantName: "CN2 GIA", wantTier: "premium", wantHop: "59.43.246.1",
			wantCross: false,
		},
		{
			// 用户实测联通：218.105 → 210.14 → 219.158，规则 2 优先于规则 5
			desc:     "广东联通实测路径：218.105 命中 9929，219.158 不夺权",
			target:   "联通",
			hops:     []string{"199.102.1.1", "162.219.1.1", "43.255.1.1", "218.105.2.1", "210.14.1.1", "219.158.1.1"},
			wantName: "9929", wantTier: "premium", wantHop: "218.105.2.1",
			wantCross: false,
		},
		{
			// 用户实测移动：223.120(AS58807) → 221.183
			desc:     "广东移动实测路径：223.120 → CMIN2",
			target:   "移动",
			hops:     []string{"199.102.1.1", "223.120.1.1", "223.120.2.1", "221.183.1.1"},
			wantName: "CMIN2", wantTier: "premium", wantHop: "223.120.1.1",
			wantCross: false,
		},
		{
			// 跨网：电信目标回程走 9929
			desc:     "跨网：电信目标走联通 9929",
			target:   "电信",
			hops:     []string{"199.102.1.1", "218.105.2.1", "219.158.1.1"},
			wantName: "9929", wantTier: "premium", wantHop: "218.105.2.1",
			wantCross: true,
		},
		{
			// 跨网：联通目标回程走 CN2
			desc:     "跨网：联通目标走 CN2 GIA",
			target:   "联通",
			hops:     []string{"199.102.1.1", "59.43.246.1", "59.43.130.1"},
			wantName: "CN2 GIA", wantTier: "premium", wantHop: "59.43.246.1",
			wantCross: true,
		},
		{
			// 169 路径也常经过 210.14，不能被弱证据抢判成 9929
			desc:     "169：只有 210.14 + 219.158，仍判 169",
			target:   "联通",
			hops:     []string{"199.102.1.1", "210.14.1.1", "219.158.1.1"},
			wantName: "169", wantTier: "standard", wantHop: "219.158.1.1",
			wantCross: false,
		},
		{
			desc:     "210.14 单独出现（无 169 骨干）时认作 9929",
			target:   "联通",
			hops:     []string{"199.102.1.1", "210.14.1.1"},
			wantName: "9929", wantTier: "premium", wantHop: "210.14.1.1",
			wantCross: false,
		},
		{
			// 223.118 属 CMI；若同路径有 223.120 则由规则 3 抢先判 CMIN2
			desc:     "CMI：223.118 判 CMI 普通线路",
			target:   "移动",
			hops:     []string{"199.102.1.1", "223.118.1.1", "221.183.1.1"},
			wantName: "CMI", wantTier: "standard", wantHop: "223.118.1.1",
			wantCross: false,
		},
		{
			desc:     "CMIN2 优先于 CMI：同时出现 223.120 / 223.118",
			target:   "移动",
			hops:     []string{"199.102.1.1", "223.120.1.1", "223.118.1.1"},
			wantName: "CMIN2", wantTier: "premium", wantHop: "223.120.1.1",
			wantCross: false,
		},
		{
			desc:     "纯 163：无 59.43，只有 202.97",
			target:   "电信",
			hops:     []string{"199.102.1.1", "202.97.12.1", "113.96.1.1"},
			wantName: "163", wantTier: "standard", wantHop: "202.97.12.1",
			wantCross: false,
		},
		{
			desc:     "CMNET 兜底：221.183",
			target:   "移动",
			hops:     []string{"199.102.1.1", "221.183.1.1"},
			wantName: "CMNET", wantTier: "standard", wantHop: "221.183.1.1",
			wantCross: false,
		},
		{
			desc:     "未命中任何骨干 → 未知",
			target:   "电信",
			hops:     []string{"1.2.3.4", "5.6.7.8"},
			wantName: "未知", wantTier: "unknown", wantHop: "",
			wantCross: false,
		},
		{
			desc:     "空路径 → 未知",
			target:   "电信",
			hops:     nil,
			wantName: "未知", wantTier: "unknown", wantHop: "",
			wantCross: false,
		},
	}

	for _, c := range cases {
		got := classifyRoute(c.hops)
		cross := c.target != "" && got.carrier != "" && got.carrier != c.target
		if got.name != c.wantName || got.tier != c.wantTier || got.hop != c.wantHop {
			t.Errorf("%s: got (%s,%s,%s), want (%s,%s,%s)", c.desc,
				got.name, got.tier, got.hop, c.wantName, c.wantTier, c.wantHop)
		}
		if cross != c.wantCross {
			t.Errorf("%s: cross = %v, want %v", c.desc, cross, c.wantCross)
		}
	}
}

// ASN 完全不可用（DNS 不通）时必须靠前缀兜底，不能整块变「未知」。
func TestClassifyHopsPrefixFallback(t *testing.T) {
	setASNResolver(t, func(string) (int, string) { return 0, "" })

	cases := []struct {
		hops []string
		want string
	}{
		{[]string{"218.30.54.1", "202.97.12.1"}, "163"},
		{[]string{"59.43.246.1"}, "CN2 GIA"},
		{[]string{"59.43.246.1", "202.97.12.1"}, "CN2 GT"},
		{[]string{"218.105.2.1"}, "9929"},
		{[]string{"210.14.1.1"}, "9929"},
		{[]string{"210.14.1.1", "219.158.1.1"}, "169"},
		{[]string{"223.120.2.1"}, "CMIN2"},
		{[]string{"223.118.1.1"}, "CMI"},
		{[]string{"221.183.1.1"}, "CMNET"},
		{[]string{"1.2.3.4"}, "未知"},
	}
	for _, c := range cases {
		if got := classifyRoute(c.hops); got.name != c.want {
			t.Errorf("fallback %v: got %s, want %s", c.hops, got.name, c.want)
		}
	}
}

func TestPathSummary(t *testing.T) {
	setASNResolver(t, func(ip string) (int, string) {
		if ip == "202.97.12.1" {
			return 4134, "CN"
		}
		return 0, ""
	})

	hops := []string{"10.0.0.1", "218.30.54.1", "202.97.12.1", "113.96.1.1"}
	got := pathSummary(hops, "202.97.12.1")
	want := "10.0.0.1 → 218.30.54.1 → 202.97.12.1(AS4134/CN)（第3跳/共4跳）"
	if got != want {
		t.Errorf("pathSummary = %q, want %q", got, want)
	}
	if got := pathSummary(hops, ""); got != "10.0.0.1 → 218.30.54.1 → 202.97.12.1 → 113.96.1.1（第4跳/共4跳）" {
		t.Errorf("pathSummary fallback = %q", got)
	}
}

func TestCarrierFromName(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"电信", "电信"},
		{"广东电信", "电信"},
		{"gd-ct", ""},
		{"广东联通", "联通"},
		{"联通 9929", "联通"},
		{"广东移动", "移动"},
		{"CMCC-GZ", "移动"},
		{"Google DNS", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := carrierFromName(c.name); got != c.want {
			t.Errorf("carrierFromName(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestParseHops(t *testing.T) {
	out := "traceroute to 202.96.209.133, 18 hops max\ntraceroute: Warning: xxx\n 1  * * *\n 2  10.0.0.1  0.5 ms\n 3  59.43.246.5  1.2 ms\n"
	hops := parseHops(out)
	if len(hops) != 2 || hops[0] != "10.0.0.1" || hops[1] != "59.43.246.5" {
		t.Fatalf("traceroute parse: %#v", hops)
	}

	// mtr -r -n 的格式与 traceroute 不同，必须也能解析
	mtrOut := "Start: 2026-11-26T10:00:00+0800\nHOST: box  Loss%  Snt   Last\n  1.|-- 10.0.0.1  0.0%  1  0.4\n  2.|-- 218.30.54.1  0.0%  1  1.2\n  3.|-- ???  100.0  1  0.0\n  4.|-- 59.43.246.1  0.0%  1  2.0\n"
	hops = parseHops(mtrOut)
	if len(hops) != 3 || hops[0] != "10.0.0.1" || hops[1] != "218.30.54.1" || hops[2] != "59.43.246.1" {
		t.Fatalf("mtr parse: %#v", hops)
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"210.21.196.6", "210.21.196.6", 0},
		{"gd-ct-v4.ip.zstaticcdn.com", "gd-ct-v4.ip.zstaticcdn.com", 0},
		{"gd-ct-v4.ip.zstaticcdn.com:80", "gd-ct-v4.ip.zstaticcdn.com", 80},
		{"1.2.3.4:443", "1.2.3.4", 443},
		{"[2400:3200::1]:8080", "2400:3200::1", 8080},
		{"  1.2.3.4  ", "1.2.3.4", 0},
		{"", "", 0},
	}
	for _, c := range cases {
		host, port := splitHostPort(c.in)
		if host != c.wantHost || port != c.wantPort {
			t.Errorf("splitHostPort(%q) = (%q,%d), want (%q,%d)", c.in, host, port, c.wantHost, c.wantPort)
		}
	}
}
