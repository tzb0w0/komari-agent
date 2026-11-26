package monitoring

import "testing"

// 判定口径与 nq 一致：第一个落地中国大陆的跳，其 ASN 决定线路。
func TestClassifyHops(t *testing.T) {
	// 用例取自用户实测的 nq 输出（广东电信 / 广东联通 / 广东移动）
	asnTable := map[string][2]interface{}{
		"199.102.1.1": {402506, "US"},
		"218.30.54.1": {4134, "CN"},  // 上海 CHINANET-US
		"59.43.246.1": {4809, "CN"},  // CN2 广州
		"202.97.12.1": {4134, "CN"},  // 163 广州
		"113.96.1.1":  {4134, "CN"},  // 广东电信
		"162.219.1.1": {10099, "US"}, // CUG 洛杉矶
		"43.255.1.1":  {10099, "HK"}, // CUG 香港
		"218.105.2.1": {9929, "CN"},  // CUII 广州
		"219.158.1.1": {4837, "CN"},  // 169 广州
		"223.120.1.1": {58807, "US"}, // CMIN2 洛杉矶
		"223.120.2.1": {58807, "CN"}, // CMIN2 上海
		"221.183.1.1": {9808, "CN"},  // CMNET
		"210.14.1.1":  {0, "CN"},     // 城域节点，无 ASN
	}
	restore := originASN
	originASN = func(ip string) (int, string) {
		if v, ok := asnTable[ip]; ok {
			return v[0].(int), v[1].(string)
		}
		return 0, ""
	}
	asnCacheMu.Lock()
	asnCache = map[string]asnInfo{}
	asnFails, asnOff = 0, false
	asnCacheMu.Unlock()
	defer func() { originASN = restore }()

	cases := []struct {
		desc     string
		hops     []string
		wantName string
		wantTier string
		wantHop  string
	}{
		{
			// nq: 广东 电信 AS402506 -> 163（路径里有 59.43，但落地 AS 是 4134）
			"广东电信：落地 AS4134 判 163，即使中途经过 CN2",
			[]string{"199.102.1.1", "218.30.54.1", "59.43.246.1", "202.97.12.1", "113.96.1.1"},
			"163", "standard", "218.30.54.1",
		},
		{
			// nq: 广东 联通 AS402506 -> 9929（香港段 AS10099 不算落地）
			"广东联通：境外 CUG 跳跳过，落地 AS9929 判 9929",
			[]string{"199.102.1.1", "162.219.1.1", "43.255.1.1", "218.105.2.1", "219.158.1.1"},
			"9929", "premium", "218.105.2.1",
		},
		{
			// nq: 广东 移动 AS402506 -> CMIN2
			"广东移动：落地 AS58807 判 CMIN2",
			[]string{"199.102.1.1", "223.120.1.1", "223.120.2.1", "221.183.1.1"},
			"CMIN2", "premium", "223.120.2.1",
		},
		{
			"跨网：电信目标落地 AS9929 就应显示 9929",
			[]string{"199.102.1.1", "218.105.2.1"},
			"9929", "premium", "218.105.2.1",
		},
		{
			"跨网：联通目标落地 AS4809 就应显示 CN2 GIA",
			[]string{"199.102.1.1", "59.43.246.1"},
			"CN2 GIA", "premium", "59.43.246.1",
		},
	}
	for _, c := range cases {
		gotName, gotTier, gotHop := classifyHops(c.hops)
		if gotName != c.wantName || gotTier != c.wantTier || gotHop != c.wantHop {
			t.Errorf("%s: got (%s,%s,%s), want (%s,%s,%s)", c.desc,
				gotName, gotTier, gotHop, c.wantName, c.wantTier, c.wantHop)
		}
	}

	// ASN 完全不可用时退回前缀表，保证不会整块变未知
	originASN = func(ip string) (int, string) { return 0, "" }
	asnCacheMu.Lock()
	asnCache = map[string]asnInfo{}
	asnFails, asnOff = 0, false
	asnCacheMu.Unlock()
	fallback := []struct {
		hops []string
		want string
	}{
		{[]string{"218.30.54.1", "202.97.12.1"}, "163"},
		{[]string{"59.43.246.1"}, "CN2 GIA"},
		{[]string{"218.105.2.1"}, "9929"},
		{[]string{"223.120.2.1"}, "CMIN2"},
		{[]string{"210.14.1.1"}, "未知"},
	}
	for _, c := range fallback {
		if got, _, _ := classifyHops(c.hops); got != c.want {
			t.Errorf("fallback %v: got %s, want %s", c.hops, got, c.want)
		}
	}
}

func TestPathSummary(t *testing.T) {
	restore := originASN
	originASN = func(ip string) (int, string) {
		if ip == "202.97.12.1" {
			return 4134, "CN"
		}
		return 0, ""
	}
	asnCacheMu.Lock()
	asnCache = map[string]asnInfo{}
	asnFails, asnOff = 0, false
	asnCacheMu.Unlock()
	defer func() { originASN = restore }()

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
