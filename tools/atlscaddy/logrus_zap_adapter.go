package atlscaddy

import (
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var levelMap = map[logrus.Level]zapcore.Level{
	logrus.PanicLevel: zap.PanicLevel,
	logrus.FatalLevel: zap.ErrorLevel,
	logrus.ErrorLevel: zap.ErrorLevel,
	logrus.WarnLevel:  zap.WarnLevel,
	logrus.InfoLevel:  zap.InfoLevel,
	logrus.DebugLevel: zap.DebugLevel,
	// zap does not have a trace level, so redirect to debug instead
	logrus.TraceLevel: zap.DebugLevel,
}

// For consistent logging output from both the atls library and caddy, this adapter redirects all logrus logging messages to zap.
type LogrusZapAdapter struct {
	Logger *zap.Logger
}

func (a *LogrusZapAdapter) Fire(entry *logrus.Entry) error {
	zapLevel := levelMap[entry.Level]

	if zapEntry := a.Logger.Check(zapLevel, entry.Message); zapEntry != nil {
		fields := make([]zap.Field, 0, len(entry.Data))
		for k, v := range entry.Data {
			fields = append(fields, zap.Any(k, v))
		}
		if c := entry.Caller; c != nil {
			// Pc != 0 is used upstream, so we do the same.
			// See: https://github.com/uber-go/zap/blob/0ab0d5aae5986395e2ca497385d977ccd7cdfc5e/logger.go#L397
			zapEntry.Caller = zapcore.NewEntryCaller(c.PC, c.File, c.Line, c.PC != 0)
		}
		zapEntry.Write(fields...)
	}
	return nil
}

func (a *LogrusZapAdapter) Levels() []logrus.Level {
	return logrus.AllLevels
}

var _ logrus.Hook = (*LogrusZapAdapter)(nil)
