package perfdata

import (
	"fmt"
	"math"

	"github.com/cataggar/LinuxTracepoints-Go/tracepoint"
)

func (r *Reader) parseClockData(data []byte) error {
	if len(data) < 24 {
		return fmt.Errorf("%w: CLOCK_DATA is shorter than 24 bytes", tracepoint.ErrTruncated)
	}
	version := r.order.Uint32(data)
	if version < 1 {
		return fmt.Errorf("%w: CLOCK_DATA version %d", tracepoint.ErrInvalid, version)
	}
	id := int32(r.order.Uint32(data[4:]))
	wall := r.order.Uint64(data[8:])
	clockTime := r.order.Uint64(data[16:])
	if r.clock.IDKnown && r.clock.ID != id {
		return fmt.Errorf("%w: CLOCKID and CLOCK_DATA IDs disagree", tracepoint.ErrInvalid)
	}
	r.clock.DataVersion, r.clock.WallClockNS, r.clock.ClockIDTimeNS = version, wall, clockTime
	r.setClockID(id)
	if off, ok := signedDifference(wall, clockTime); ok {
		r.clock.EpochOffset, r.clock.EpochOffsetKnown = off, true
	} else {
		r.clock.EpochOffsetKnown = false
	}
	return nil
}

func signedDifference(a, b uint64) (int64, bool) {
	if a >= b {
		d := a - b
		if d > math.MaxInt64 {
			return 0, false
		}
		return int64(d), true
	}
	d := b - a
	if d > uint64(math.MaxInt64)+1 {
		return 0, false
	}
	if d == uint64(math.MaxInt64)+1 {
		return math.MinInt64, true
	}
	return -int64(d), true
}

func (r *Reader) setClockID(id int32) {
	r.clock.ID, r.clock.IDKnown, r.clock.Clock = id, true, linuxClock(id)
	if id == 0 && r.clock.DataVersion == 0 {
		r.clock.EpochOffset, r.clock.EpochOffsetKnown = 0, true
	}
}

func linuxClock(id int32) tracepoint.Clock {
	switch id {
	case 0:
		return tracepoint.ClockRealtime
	case 1:
		return tracepoint.ClockMonotonic
	case 7:
		return tracepoint.ClockBoot
	case 11:
		return tracepoint.ClockTAI
	default:
		return tracepoint.ClockUnknown
	}
}

func (r *Reader) timestamp(ns uint64) tracepoint.Timestamp {
	return tracepoint.Timestamp{
		Nanoseconds: ns, Clock: r.clock.Clock,
		EpochOffset: r.clock.EpochOffset, EpochOffsetKnown: r.clock.EpochOffsetKnown,
	}
}
