package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func StructuredLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		
		msg := "HTTP request"
		if len(c.Errors) > 0 {
			msg = c.Errors.String()
		}

		event := log.Info()
		if path == "/health" {
			event = log.Debug()
		}
		if c.Writer.Status() >= http.StatusBadRequest {
			event = log.Error()
		}

		event.
			Int("status", c.Writer.Status()).
			Str("method", c.Request.Method).
			Str("path", path).
			Str("query", query).
			Str("ip", c.ClientIP()).
			Str("user-agent", c.Request.UserAgent()).
			Dur("latency", latency).
			Msg(msg)
	}
}
