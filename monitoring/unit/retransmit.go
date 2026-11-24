package monitoring

// retransmit.go —— TCP 重传率采集
//
// Linux 内核在 /proc/net/snmp 中维护 TcpExt 统计，其中 TcpRetransSegs 是
// 累计重传报文数，OutSegs 是累计发送报文数。两次采样做差即可得到
// 区间重传率 = (重传增量 / 发送增量) * 100。
// 非 Linux 平台没有该文件，降级返回 0，不影响 agent 正常运行。

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
)

// RetransmitReport 上报的重传数据。
type RetransmitReport struct {
	Rate      float64 `json:"rate"`      // 重传率百分比
	Retrans   uint64  `json:"retrans"`   // 本次区间重传报文数
	OutSegs   uint64  `json:"out_segs"`  // 本次区间发送报文数
	Available bool    `json:"available"` // 是否采集成功
}

var (
	retransMu       sync.Mutex
	lastRetransSegs uint64
	lastOutSegs     uint64
	hasLastSample   bool
)

// CollectRetransmit 采集自上次调用以来的 TCP 重传率。
func CollectRetransmit() RetransmitReport {
	retransMu.Lock()
	defer retransMu.Unlock()

	curRetrans, curOut, ok := readTCPCounters()
	if !ok {
		return RetransmitReport{Available: false}
	}

	report := RetransmitReport{Available: true}
	if hasLastSample && curOut > lastOutSegs {
		dRetrans := curRetrans - lastRetransSegs
		dOut := curOut - lastOutSegs
		report.Retrans = dRetrans
		report.OutSegs = dOut
		report.Rate = float64(dRetrans) / float64(dOut) * 100
		if report.Rate < 0 {
			report.Rate = 0
		}
	}

	lastRetransSegs = curRetrans
	lastOutSegs = curOut
	hasLastSample = true
	return report
}

// readTCPCounters 从 /proc/net/snmp 读取 TcpRetransSegs 和 OutSegs。
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
