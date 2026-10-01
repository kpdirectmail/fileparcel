package certs

import (
	"context"
	"log/slog"
	"slices"
	"sort"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// certmagic logs through zap. Without a logger it builds its own, which
// writes to stderr in zap's format and bypasses the FileParcel log entirely,
// so ACME diagnostics would be lost in a service install. zapLogger wraps a
// *slog.Logger in the minimal zapcore.Core certmagic needs, so its records
// arrive as ordinary FileParcel log lines (subsystem=acme).
//
// This is the only place that imports zap; it is otherwise an indirect
// dependency of certmagic.
func zapLogger(l *slog.Logger) *zap.Logger { return zap.New(&slogCore{log: l}) }

type slogCore struct {
	log    *slog.Logger
	fields []zapcore.Field
}

func (c *slogCore) Enabled(l zapcore.Level) bool {
	return c.log.Enabled(context.Background(), slogLevel(l))
}

func (c *slogCore) With(f []zapcore.Field) zapcore.Core {
	return &slogCore{log: c.log, fields: append(slices.Clip(c.fields), f...)}
}

func (c *slogCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(e.Level) {
		return ce.AddCore(e, c)
	}
	return ce
}

func (c *slogCore) Write(e zapcore.Entry, fs []zapcore.Field) error {
	enc := zapcore.NewMapObjectEncoder()
	for _, f := range append(slices.Clip(c.fields), fs...) {
		f.AddTo(enc)
	}
	keys := make([]string, 0, len(enc.Fields))
	for k := range enc.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	attrs := make([]slog.Attr, 0, len(keys)+1)
	if e.LoggerName != "" {
		attrs = append(attrs, slog.String("logger", e.LoggerName))
	}
	for _, k := range keys {
		attrs = append(attrs, slog.Any(k, enc.Fields[k]))
	}
	c.log.LogAttrs(context.Background(), slogLevel(e.Level), e.Message, attrs...)
	return nil
}

func (c *slogCore) Sync() error { return nil }

// slogLevel maps zap levels onto slog levels (zap's DPanic/Panic/Fatal all
// become Error; nothing in this adapter panics or exits).
func slogLevel(l zapcore.Level) slog.Level {
	switch {
	case l <= zapcore.DebugLevel:
		return slog.LevelDebug
	case l == zapcore.InfoLevel:
		return slog.LevelInfo
	case l == zapcore.WarnLevel:
		return slog.LevelWarn
	}
	return slog.LevelError
}
