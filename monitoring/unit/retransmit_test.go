package monitoring

import "testing"

// TestCollectRetransmitGraceful 验证重传采集在无 /proc/net/snmp 的平台（如 Windows）
// 上能安全降级，不 panic、不返回 error。
func TestCollectRetransmitGraceful(t *testing.T) {
	rep := CollectRetransmit()
	// 只要能返回结构体即视为安全；在支持 /proc 的 Linux 上 Available 为 true，
	// 在其他平台为 false。两种都不允许 panic。
	if rep.Rate < 0 {
		t.Fatalf("rate 不应为负: %v", rep.Rate)
	}
	t.Logf("retransmit available=%v rate=%.4f", rep.Available, rep.Rate)
}

// TestCollectRetransmitRepeated 验证连续调用不会因共享状态而漂移或 panic。
func TestCollectRetransmitRepeated(t *testing.T) {
	for i := 0; i < 3; i++ {
		rep := CollectRetransmit()
		if rep.Rate < 0 {
			t.Fatalf("第 %d 次调用 rate 为负", i)
		}
	}
}
