package monitoring

import "testing"

// 判定口径：只看「跨境落地那一跳」——第一个进入国内骨干网的节点。
func TestClassifyHops(t *testing.T) {
	cases := []struct {
		desc     string
		hops     []string
		wantName string
		wantTier string
	}{
		{
			"电信 163：218.30 是国际出口，不算落地，落到 202.97",
			[]string{"10.0.0.1", "186.244.1.1", "218.30.54.1", "202.97.12.1", "113.96.1.1"},
			"163", "standard",
		},
		{
			"电信 CN2 GIA：218.30 之后落到 59.43",
			[]string{"10.0.0.1", "218.30.54.1", "59.43.246.1", "59.43.130.1"},
			"CN2 GIA", "premium",
		},
		{
			"联通 9929：落地在 218.105",
			[]string{"162.219.1.1", "43.255.1.1", "218.105.2.1", "210.14.1.1", "219.158.1.1"},
			"9929", "premium",
		},
		{
			"联通 9929 另一段：210.51",
			[]string{"218.105.1.1", "210.51.1.1"},
			"9929", "premium",
		},
		{
			"联通 169：落地在 219.158",
			[]string{"162.219.1.1", "219.158.1.1", "219.158.2.1"},
			"169", "standard",
		},
		{
			"移动普通 CMI：223.120 不能标成 CMIN2",
			[]string{"223.120.1.1", "221.183.1.1", "111.24.1.1"},
			"CMI", "standard",
		},
		{
			"移动 CMIN2：223.119 才是精品网",
			[]string{"223.119.1.1", "223.118.1.1", "221.176.1.1"},
			"CMIN2", "premium",
		},
		{
			"移动 CMNET：落地在 221.183",
			[]string{"111.24.1.1", "221.183.1.1"},
			"CMNET", "standard",
		},
		{
			"只有城域节点时不做线路命名",
			[]string{"210.14.1.1"},
			"未知", "unknown",
		},
		{
			"未知路径",
			[]string{"1.2.3.4", "5.6.7.8"},
			"未知", "unknown",
		},
		{"空路径", nil, "未知", "unknown"},
	}
	for _, c := range cases {
		gotName, gotTier, _ := classifyHops(c.hops)
		if gotName != c.wantName || gotTier != c.wantTier {
			t.Errorf("%s: got (%s,%s), want (%s,%s)", c.desc, gotName, gotTier, c.wantName, c.wantTier)
		}
	}
}

func TestPathSummary(t *testing.T) {
	hops := []string{"10.0.0.1", "218.30.54.1", "202.97.12.1", "113.96.1.1"}
	got := pathSummary(hops, "202.97.12.1")
	want := "10.0.0.1 → 218.30.54.1 → 202.97.12.1（第3跳/共4跳）"
	if got != want {
		t.Errorf("pathSummary = %q, want %q", got, want)
	}
	// 未命中时回落到最后一跳，仍可看出确实探测过
	got = pathSummary(hops, "")
	if got != "10.0.0.1 → 218.30.54.1 → 202.97.12.1 → 113.96.1.1（第4跳/共4跳）" {
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
