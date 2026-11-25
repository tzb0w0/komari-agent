package monitoring

import "testing"

func TestClassifyHops(t *testing.T) {
	cases := []struct {
		name     string
		hops     []string
		wantName string
		wantTier string
	}{
		{"CN2 GIA 优先于 163", []string{"10.0.0.1", "202.97.12.1", "59.43.246.5", "58.60.188.1"}, "CN2 GIA", "premium"},
		{"纯 163", []string{"10.0.0.1", "202.97.12.1", "61.152.1.1"}, "163", "standard"},
		{"联通 9929", []string{"172.16.0.1", "218.30.54.1", "210.22.70.1"}, "9929", "premium"},
		{"联通 169", []string{"219.158.16.1", "210.22.70.1"}, "169", "standard"},
		{"移动 CMI", []string{"223.120.2.1", "221.176.1.1"}, "CMI", "standard"},
		{"未知路径", []string{"1.2.3.4", "5.6.7.8"}, "未知", "unknown"},
		{"空路径", nil, "未知", "unknown"},
	}
	for _, c := range cases {
		gotName, gotTier, _ := classifyHops(c.hops)
		if gotName != c.wantName || gotTier != c.wantTier {
			t.Errorf("%s: got (%s,%s), want (%s,%s)", c.name, gotName, gotTier, c.wantName, c.wantTier)
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
