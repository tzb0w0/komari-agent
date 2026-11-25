package monitoring

// retransmit.go —— TCP 重传率采集
//
// Linux 内核在 /proc/net/snmp 中维护 TCP 统计，其中 RetransSegs 是累计重传报文数，
// OutSegs 是累计发送报文数。对同一个「采样窗口」的首尾两次采样做差即可得到
// 区间重传率 = (重传增量 / 发送增量) * 100。
//
// 为了得到有统计意义的数值，默认按 30 分钟为一个窗口（可由面板配置下发）：
// 窗口未结束时直接返回上一次算好的结果，窗口结束时重算并缓存。
// 因此卡片上的重传率最多每 30 分钟变化一次，这是预期行为。
//
// 非 Linux 平台没有 /proc/net/snmp，降级返回 Available=false，不影响 agent 运行。

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RetransmitReport 上报的重传数据。
type RetransmitReport struct {
	Rate      float64 `json:"rate"`      // 窗口内重传率百分比
	Retrans   uint64  `json:"retrans"`   // 窗口内重传报文数
	OutSegs   uint64  `json:"out_segs"`  // 窗口内发送报文数
	Available bool    `json:"available"` // 是否已有可用的窗口统计
}

var (
	retransMu sync.Mutex

	// 采样窗口长度，默认 30 分钟。
	retransWindow = 30 * time.Minute

	windowStart     time.Time // 当前窗口起点
	startRetransSeg uint64    // 窗口起点的累计重传数
	startOutSegs    uint64    // 窗口起点的累计发送数
	windowReady     bool      // 是否已建立窗口起点

	cached    RetransmitReport // 最近一次窗口结算结果
	hasCached bool
)

// SetRetransmitInterval 设置重传采样窗口（<=0 时忽略）。
func SetRetransmitInterval(d time.Duration) {
	if d <= 0 {
		return
	}
	retransMu.Lock()
	retransWindow = d
	retransMu.Unlock()
}

// CollectRetransmit 返回当前窗口的重传率。
// 窗口未满时返回上一次结算结果；尚未完成任何窗口时返回 Available=false。
func CollectRetransmit() RetransmitReport {
	retransMu.Lock()
	defer retransMu.Unlock()

	curRetrans, curOut, ok := readTCPCounters()
	if !ok {
		return RetransmitReport{Available: false}
	}

	now := time.Now()
	if !windowReady {
		// 首次调用：只记录窗口起点，此时还没有可结算的区间
		windowStart, startRetransSeg, startOutSegs = now, curRetrans, curOut
		windowReady = true
		return RetransmitReport{Available: false}
	}

	if now.Sub(windowStart) < retransWindow {
		// 窗口未满：返回上次结算结果
		if hasCached {
			return cached
		}
		return RetransmitReport{Available: false}
	}

	// 窗口已满：结算本窗口
	report := RetransmitReport{Available: true}
	if curOut > startOutSegs {
		dRetrans := curRetrans - startRetransSeg
		dOut := curOut - startOutSegs
		report.Retrans = dRetrans
		report.OutSegs = dOut
		report.Rate = float64(dRetrans) / float64(dOut) * 100
		if report.Rate < 0 {
			report.Rate = 0
		}
	}

	// 本窗口结束，起点推进到当前采样
	windowStart, startRetransSeg, startOutSegs = now, curRetrans, curOut
	cached, hasCached = report, true
	return report
}

// readTCPCounters 从 /proc/net/snmp 读取 RetransSegs 和 OutSegs。
func readTCPCounters() (retrans uint64, outSegs uint64, ok bool) {
	f, err := os.Open("/proc/net/snmp")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var header []string
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		key := fields[0]
		// /proc/net/snmp 每个表有 header 行和 values 行，key 形如 "Tcp:" / "TcpExt:"
		if key == "Tcp:" && header == nil {
			header = fields[1:]
			continue
		}
		if key == "Tcp:" && header != nil {
			retransIdx, outIdx := -1, -1
			for i, name := range header {
				switch name {
				case "RetransSegs":
					retransIdx = i
				case "OutSegs":
					outIdx = i
				}
			}
			if retransIdx >= 0 && outIdx >= 0 && retransIdx < len(fields)-1 && outIdx < len(fields)-1 {
				r, err1 := strconv.ParseUint(fields[retransIdx+1], 10, 64)
				o, err2 := strconv.ParseUint(fields[outIdx+1], 10, 64)
				if err1 == nil && err2 == nil {
					return r, o, true
				}
			}
			return 0, 0, false
		}
	}
	return 0, 0, false
}
