package logger

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

func NewLogger(isProd bool) zerolog.Logger {
	if isProd {
		logger := zerolog.New(os.Stdout).With().Timestamp().Caller().Logger().Level(zerolog.InfoLevel)
		zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
		return logger
	}

	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}

	output.FormatLevel = func(i any) string {
		level := strings.ToUpper(fmt.Sprintf("%s", i))
		var colorStart, colorEnd string
		switch level {
		case "INFO":
			colorStart = "\x1b[32m" 
		case "DEBUG":
			colorStart = "\x1b[34m" 
		case "ERROR", "FATAL":
			colorStart = "\x1b[31m"
		case "WARN":
			colorStart = "\x1b[33m"
		default:
			colorStart = ""
		}
		colorEnd = "\x1b[0m"

		return fmt.Sprintf("| %s%-6s%s|", colorStart, level, colorEnd)
	}

	output.FormatMessage = func(i any) string {
		return fmt.Sprintf("[ %s ]", i)
	}
	output.FormatFieldName = func(i any) string {
		return fmt.Sprintf("%s:", i)
	}
	output.FormatFieldValue = func(i any) string {
		return strings.ToUpper(fmt.Sprintf("%s", i))
	}

	logger := zerolog.New(output).With().
		Timestamp().
		Caller().
		Logger()

	return logger
}
