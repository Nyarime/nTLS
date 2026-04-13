package nrtp

import (
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// SmartTransport 智能传输切换（UDP/TCP自动选择）
type SmartTransport struct {
	mode          atomic.Int32
	mu            sync.Mutex
	sent          int64
	recv          int64
	rttSum        time.Duration
	rttCount      int64
	checkInterval time.Duration
}

// TransportMode 传输模式
type TransportMode int32

const (
	ModeUDP       TransportMode = 0
	ModeUDPviaTCP TransportMode = 1
	ModeTCP       TransportMode = 2
)

func (m TransportMode) String() string {
	switch m {
	case ModeUDP:
		return "UDP"
	case ModeUDPviaTCP:
		return "UDP-over-TCP"
	case ModeTCP:
		return "TCP"
	default:
		return "unknown"
	}
}

// NewSmartTransport 创建智能传输选择器
func NewSmartTransport() *SmartTransport {
	st := &SmartTransport{checkInterval: 10 * time.Second}
	st.mode.Store(int32(ModeUDP))
	go st.monitor()
	return st
}

// Mode 获取当前模式
func (st *SmartTransport) Mode() TransportMode {
	return TransportMode(st.mode.Load())
}

// RecordSend 记录发送
func (st *SmartTransport) RecordSend() {
	st.mu.Lock()
	st.sent++
	st.mu.Unlock()
}

// RecordRecv 记录接收+RTT
func (st *SmartTransport) RecordRecv(rtt time.Duration) {
	st.mu.Lock()
	st.recv++
	st.rttSum += rtt
	st.rttCount++
	st.mu.Unlock()
}

func (st *SmartTransport) monitor() {
	ticker := time.NewTicker(st.checkInterval)
	for range ticker.C {
		st.evaluate()
	}
}

func (st *SmartTransport) evaluate() {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.sent == 0 {
		return
	}

	lossRate := float64(st.sent-st.recv) / float64(st.sent)

	var avgRTT time.Duration
	if st.rttCount > 0 {
		avgRTT = st.rttSum / time.Duration(st.rttCount)
	}

	oldMode := TransportMode(st.mode.Load())
	var newMode TransportMode

	switch {
	case lossRate < 0.02 && avgRTT < 100*time.Millisecond:
		newMode = ModeUDP
	case lossRate < 0.10:
		newMode = ModeUDPviaTCP
	default:
		newMode = ModeTCP
	}

	if newMode != oldMode {
		st.mode.Store(int32(newMode))
		log.Printf("[NRTP] 传输切换: %s → %s (丢包=%.1f%% RTT=%v)",
			oldMode, newMode, lossRate*100, avgRTT)
	}

	// 重置
	st.sent = 0
	st.recv = 0
	st.rttSum = 0
	st.rttCount = 0
}

// AutoFallback 传输层自动降级
type AutoFallback struct {
	Primary   string
	Secondary string
	current   string
	failures  int64
	threshold int64
	degraded  atomic.Bool
	lastTry   time.Time
	mu        sync.Mutex
}

// NewAutoFallback 创建自动降级
func NewAutoFallback(primary, secondary string, threshold int) *AutoFallback {
	if threshold <= 0 {
		threshold = 3
	}
	return &AutoFallback{
		Primary:   primary,
		Secondary: secondary,
		current:   primary,
		threshold: int64(threshold),
	}
}

func (af *AutoFallback) RecordSuccess() {
	af.mu.Lock()
	defer af.mu.Unlock()
	af.failures = 0
	if af.degraded.Load() {
		af.degraded.Store(false)
		af.current = af.Primary
		log.Printf("[NRTP] ✅ 恢复: %s", af.Primary)
	}
}

func (af *AutoFallback) RecordFailure() {
	af.mu.Lock()
	defer af.mu.Unlock()
	af.failures++
	if af.failures >= af.threshold && !af.degraded.Load() {
		af.degraded.Store(true)
		af.current = af.Secondary
		af.lastTry = time.Now()
		log.Printf("[NRTP] ⚠️ 降级: %s → %s (%d次失败)", af.Primary, af.Secondary, af.failures)
	}
}

func (af *AutoFallback) Mode() string {
	if af.degraded.Load() && time.Since(af.lastTry) > 5*time.Minute {
		af.mu.Lock()
		af.lastTry = time.Now()
		af.mu.Unlock()
		return af.Primary // 定期尝试恢复
	}
	af.mu.Lock()
	defer af.mu.Unlock()
	return af.current
}
