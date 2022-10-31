package waf

import (
	"net/http"
	"time"

	"github.com/patrickmn/go-cache"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

type RateLimit struct {
	cache  *cache.Cache
	logger *zap.Logger
	bucket int
	rate   float64
}

func NewRateLimit(logger *zap.Logger, rateLimitBucket int, rateLimitRate float64) *RateLimit {
	return &RateLimit{
		cache:  cache.New(5*time.Minute, 10*time.Minute), //缓存时间和扫描时间
		logger: logger,
		bucket: rateLimitBucket, //桶大小
		rate:   rateLimitRate,   //桶速率
	}
}

func (rateLimit *RateLimit) detect(remoteIp string, r *http.Request) bool {

	requestKey := remoteIp + r.Host
	// rateLimit.logger.Info("rate limiter request key is " + requestKey)
	var limiter *rate.Limiter

	if val, found := rateLimit.cache.Get(requestKey); found {
		limiter = val.(*rate.Limiter)
	} else {
		limiter = rate.NewLimiter(rate.Limit(rateLimit.rate), rateLimit.bucket)
		rateLimit.cache.Set(requestKey, limiter, cache.DefaultExpiration)
	}

	return !limiter.Allow()
}
