package models

import (
	"math"
	"time"
)

func Float64Time(f float64) time.Time {
	i, f := math.Modf(f)
	return time.Unix(int64(i), int64(f*1e9))
}
