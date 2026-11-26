package main

import (
	"fmt"
	"log"
	"strings"
	"sync/atomic"
)

// Log levels, most verbose first.  Each level includes everything below it.
//
//	trace    request headers and bodies, rendered templates, destination responses, template data
//	debug    every router loaded, matcher evaluation
//	info     startup and reload summaries
//	warning  anything that loses or may lose an alert: rejected routers, failed sends, refused payloads
type logLevel int32

const (
	logLevelTrace logLevel = iota
	logLevelDebug
	logLevelInfo
	logLevelWarning
)

// Trace by default, which is what spitter logged before the level became configurable
var currentLogLevel atomic.Int32

// setLogLevel selects the level by name: trace, debug, info or warning (warn)
func setLogLevel(name string) error {
	var l logLevel
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "trace":
		l = logLevelTrace
	case "debug":
		l = logLevelDebug
	case "info":
		l = logLevelInfo
	case "warning", "warn":
		l = logLevelWarning
	default:
		return fmt.Errorf("unknown log level %q; expected trace, debug, info or warning", name)
	}
	currentLogLevel.Store(int32(l))
	return nil
}

func logEnabled(l logLevel) bool {
	return l >= logLevel(currentLogLevel.Load())
}

func logAt(l logLevel, format string, args ...any) {
	if logEnabled(l) {
		log.Printf(format, args...)
	}
}

func tracef(format string, args ...any) { logAt(logLevelTrace, format, args...) }
func debugf(format string, args ...any) { logAt(logLevelDebug, format, args...) }
func infof(format string, args ...any)  { logAt(logLevelInfo, format, args...) }
func warnf(format string, args ...any)  { logAt(logLevelWarning, format, args...) }

// logExcerpt returns at most max bytes of b for a log line, saying so when it cut something off
func logExcerpt(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return fmt.Sprintf("%s... (truncated: %d of %d bytes shown)", b[:max], max, len(b))
}
