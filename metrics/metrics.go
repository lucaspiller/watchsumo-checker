package metrics

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"runtime"
	"sync/atomic"
	"time"
)

var (
	atomicUp        uint32
	atomicDown      uint32
	atomicCheckTime uint64
)

// AddUp increments up counter
func AddUp() {
	atomic.AddUint32(&atomicUp, 1)
}

// AddDown increments down counter
func AddDown() {
	atomic.AddUint32(&atomicDown, 1)
}

// AddCheckTime adds check time
func AddCheckTime(d time.Duration) {
	atomic.AddUint64(&atomicCheckTime, uint64(d.Milliseconds()))
}

// Start metrics
func Start(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				// Wait for timer to expire
				logMetrics()
			}
		}
	}()
}

func logMetrics() {
	up := atomic.SwapUint32(&atomicUp, 0)
	down := atomic.SwapUint32(&atomicDown, 0)
	checkTime := atomic.SwapUint64(&atomicCheckTime, 0)

	checks := up + down
	var avg uint64
	if checks > 0 {
		avg = checkTime / uint64(checks)
	}

	goroutines := runtime.NumGoroutine()

	log.Info(fmt.Sprintf("metrics checks=%d up=%d down=%d avg=%dms goroutines=%d", checks, up, down, avg, goroutines))
}
