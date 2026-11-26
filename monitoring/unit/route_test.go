package monitoring

import "testing"

// 用例覆盖用户实测出来的错判场景：跨境回程常先经过别家运营商中转，
// 必须按「目的运营商自己网络里最先出现的那一跳」定线路。
func TestClassifyHops(t *testing.T) {
	cases := []struct {
		desc     string
		hops     []string
		carrier  string
		wantName string
		wantTier string
	}{
		{
			// 用户反馈的原 bug：电信目标经联通 9929 中转，被错标成 9929
			"广东电信：CUG -> 9929 中转 -> 163，应判 163",
			[]string{"10.0.0.1", "186.244.1.1", "162.219.1.1", "218.105.2.1", "210.14.1.1", "202.97.1.1", "113.96.1.1"},
			"电信", "163", "standard",
		},
		{
			"广东联通：9929 -> 169，取联通最早一跳 9929",
			[]string{"162.219.1.1", "43.255.1.1", "218.105.2.1", "210.14.1.1", "219.158.1.1"},
			"联通", "9929", "premium",
		},
		{
			"广东移动：CMI -> CMNET，普通 CMI 不能标成 CMIN2",
			[]string{"223.120.1.1", "221.183.1.1", "111.24.1.1", "211.136.1.1"},
			"移动", "CMI", "standard",
		},
		{
			"移动 CMIN2：223.119 段才是精品网",
			[]string{"223.119.1.1", "223.118.1.1", "221.176.1.1"},
			"移动", "CMIN2", "premium",
		},
		{
			// 用户反馈：CN2 GIA 被标成 9929，根因是 218.30（电信国际出口）被误映射
			"电信 CN2 GIA：218.30 国际出口不算线路，落到 59.43",
			[]string{"10.0.0.1", "218.30.54.1", "59.43.246.1", "59.43.130.1"},
			"电信", "CN2 GIA", "premium",
		},
		{
			"电信 163：218.30 之后进 202.97",
			[]string{"218.30.54.1", "202.97.1.1", "202.97.2.1"},
			"电信", "163", "standard",
		},
		{
			"联通 9929 另一段 210.51",
			[]string{"218.105.1.1", "210.51.1.1"},
			"联通", "9929", "premium",
		},
		{
			"运营商未知时退化为第一个骨干命中",
			[]string{"218.105.2.1", "202.97.1.1"},
			"", "9929", "premium",
		},
		{
			"只有城域节点时不做线路命名",
			[]string{"210.14.1.1"},
			"电信", "未知", "unknown",
		},
		{
			"未知路径",
			[]string{"1.2.3.4", "5.6.7.8"},
			"移动", "未知", "unknown",
		},
		{"空路径", nil, "", "未知", "unknown"},
	}
	for _, c := range cases {
		gotName, gotTier, _ := classifyHops(c.hops, c.carrier)
		if gotName != c.wantName || gotTier != c.wantTier {
			t.Errorf("%s: got (%s,%s), want (%s,%s)", c.desc, gotName, gotTier, c.wantName, c.wantTier)
		}
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
