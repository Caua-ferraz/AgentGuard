package audit

// EntryTransform rewrites an entry before it is stored — for example to mask
// secrets. It must return a copy and never modify maps it shares with the
// caller.
type EntryTransform func(Entry) Entry

// WithTransform wraps a Logger so every entry is passed through t before it
// is written. Query and Close pass through. Path is forwarded when inner has
// one, so the replay checkpoint keeps working behind the wrapper.
func WithTransform(inner Logger, t EntryTransform) Logger {
	if t == nil {
		return inner
	}
	return &transformLogger{inner: inner, t: t}
}

type transformLogger struct {
	inner Logger
	t     EntryTransform
}

func (l *transformLogger) Log(e Entry) error { return l.inner.Log(l.t(e)) }

func (l *transformLogger) Query(f QueryFilter) ([]Entry, error) { return l.inner.Query(f) }

func (l *transformLogger) Close() error { return l.inner.Close() }

// Path reports the inner logger's file path, or "" when it has none (the
// store-backed logger), in which case the server falls back to Query.
func (l *transformLogger) Path() string {
	if pr, ok := l.inner.(interface{ Path() string }); ok {
		return pr.Path()
	}
	return ""
}
