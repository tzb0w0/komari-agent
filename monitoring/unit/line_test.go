package monitoring

import "testing"

// TestMatchLineByASN 验证 ASN -> 线路 的自动识别规则。
func TestMatchLineByASN(t *testing.T) {
	cases := []struct {
		asn      int
		wantID   string
		wantName string
	}{
		{4809, "cn2gia", "CN2 GIA"},
		{4812, "cn2gia", "CN2 GIA"},
		{9929, "9929", "9929"},
		{4837, "4837", "4837"},
		{58807, "cmin", "CMIN"},
		{9808, "cmin", "CMIN"},
		{4134, "163", "163"},
		{0, "", ""},
		{99999, "", ""},
	}
	for _, c := range cases {
		got := matchLineByASN(c.asn)
		if c.wantID == "" {
			if got != nil {
				t.Errorf("ASN %d: 期望未识别, 得到 %s", c.asn, got.id)
			}
			continue
		}
		if got == nil {
			t.Errorf("ASN %d: 期望 %s, 得到未识别", c.asn, c.wantName)
			continue
		}
		if got.id != c.wantID || got.name != c.wantName {
			t.Errorf("ASN %d: 期望 %s/%s, 得到 %s/%s", c.asn, c.wantID, c.wantName, got.id, got.name)
		}
	}
}
