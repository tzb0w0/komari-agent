package monitoring

import "testing"

// 用例取自用户 nexttrace(nq) 的真实三网回程路径
func TestClassifyHops(t *testing.T) {
	cases := []struct {
		desc     string
		hops     []string
		wantName string
		wantTier string
	}{
		{
			"广东电信：CUG -> 9929 -> 163",
			[]string{"10.0.0.1", "186.244.1.1", "162.219.1.1", "218.105.2.1", "210.14.1.1", "202.97.1.1", "113.96.1.1"},
			"9929", "premium",
		},
		{
			"广东联通：CUG -> 9929 -> 169",
			[]string{"162.219.1.1", "43.255.1.1", "218.105.2.1", "210.14.1.1", "219.158.1.1"},
			"9929", "premium",
		},
		{
			"广东移动：CMIN2 -> CMNET",
			[]string{"223.120.1.1", "221.183.1.1", "111.24.1.1", "211.136.1.1"},
			"CMIN2", "premium",
		},
		{
			"电信先入 163 再出现 CN2 节点时，按先到者算 163",
			[]string{"202.97.1.1", "59.43.1.1"},
			"163", "standard",
		},
		{
			"先出现 CN2 GIA 节点",
			[]string{"59.43.1.1", "202.97.1.1"},
			"CN2 GIA", "premium",
		},
		{
			"只有城域节点",
			[]string{"210.14.1.1"},
			"联通", "standard",
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

func TestParseHops(t *testing.T) {
	out := "traceroute to 202.96.209.133, 18 hops max\ntraceroute: Warning: xxx\n 1  * * *\n 2  10.0.0.1  0.5 ms\n 3  59.43.246.5  1.2 ms\n"
	hops := parseHops(out)
	if len(hops) != 2 || hops[0] != "10.0.0.1" || hops[1] != "59.43.246.5" {
		t.Fatalf("unexpected hops: %#v", hops)
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
