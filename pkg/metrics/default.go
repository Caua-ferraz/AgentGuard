package metrics

// Package-level delegates to the Default registry. Call sites across the
// binaries use these; only code that needs an isolated registry (tests,
// future embedders) holds a *Registry directly.

import (
	"io"
	"time"
)

// -- Decision counters --

func IncDecision(decision string) { Default.IncDecision(decision) }
func IncRateLimited()             { Default.IncRateLimited() }
func IncApprovalReplayMismatch()  { Default.IncApprovalReplayMismatch() }
func ChecksTotal() uint64         { return Default.ChecksTotal() }
func AllowedTotal() uint64        { return Default.AllowedTotal() }
func DeniedTotal() uint64         { return Default.DeniedTotal() }
func ApprovalTotal() uint64       { return Default.ApprovalTotal() }
func RateLimitedTotal() uint64    { return Default.RateLimitedTotal() }
func ApprovalReplayMismatchTotal() uint64 {
	return Default.ApprovalReplayMismatchTotal()
}
func IncApprovalReplayRefused(reason string) { Default.IncApprovalReplayRefused(reason) }
func ApprovalReplayRefusedTotal(reason string) uint64 {
	return Default.ApprovalReplayRefusedTotal(reason)
}

// -- Labeled counters --

func IncRequestRejected(reason string) { Default.IncRequestRejected(reason) }
func RequestRejectedSnapshot() map[string]uint64 {
	return Default.RequestRejectedSnapshot()
}
func IncApprovalEvicted(reason string)        { Default.IncApprovalEvicted(reason) }
func ApprovalEvictedFor(reason string) uint64 { return Default.ApprovalEvictedFor(reason) }
func IncRateLimitBucketEvicted(scope string)  { Default.IncRateLimitBucketEvicted(scope) }
func RateLimitBucketEvictedFor(scope string) uint64 {
	return Default.RateLimitBucketEvictedFor(scope)
}
func IncSSEEventDropped(reason string)        { Default.IncSSEEventDropped(reason) }
func SSEEventDroppedFor(reason string) uint64 { return Default.SSEEventDroppedFor(reason) }
func IncNotifyDropped(notifier, reason string) {
	Default.IncNotifyDropped(notifier, reason)
}
func NotifyDroppedSnapshot() map[notifyDroppedKey]uint64 {
	return Default.NotifyDroppedSnapshot()
}
func NotifyDroppedFor(notifier, reason string) uint64 {
	return Default.NotifyDroppedFor(notifier, reason)
}

// -- LLM-proxy series --

func IncLLMProxyBufferOverflow(provider string) {
	Default.IncLLMProxyBufferOverflow(provider)
}
func LLMProxyBufferOverflowFor(provider string) uint64 {
	return Default.LLMProxyBufferOverflowFor(provider)
}
func IncLLMProxyNonStreamingOverflow(provider string) {
	Default.IncLLMProxyNonStreamingOverflow(provider)
}
func LLMProxyNonStreamingOverflowFor(provider string) uint64 {
	return Default.LLMProxyNonStreamingOverflowFor(provider)
}
func IncLLMProxyProtocolViolation(provider string) {
	Default.IncLLMProxyProtocolViolation(provider)
}
func LLMProxyProtocolViolationFor(provider string) uint64 {
	return Default.LLMProxyProtocolViolationFor(provider)
}
func SetLLMProxyStreamsActive(n int64)       { Default.SetLLMProxyStreamsActive(n) }
func AddLLMProxyStreamsActive(d int64) int64 { return Default.AddLLMProxyStreamsActive(d) }
func IncLLMProxyStreamsRejected()            { Default.IncLLMProxyStreamsRejected() }
func LLMProxyStreamsActive() int64           { return Default.LLMProxyStreamsActive() }
func LLMProxyStreamsRejectedTotal() uint64   { return Default.LLMProxyStreamsRejectedTotal() }

// -- Audit series --

func IncAuditCorruptLine()           { Default.IncAuditCorruptLine() }
func AuditCorruptLinesTotal() uint64 { return Default.AuditCorruptLinesTotal() }
func SetAuditReplayDuration(d time.Duration) {
	Default.SetAuditReplayDuration(d)
}
func AddAuditReplayEntries(n uint64)  { Default.AddAuditReplayEntries(n) }
func IncAuditRotation()               { Default.IncAuditRotation() }
func AuditReplayEntriesTotal() uint64 { return Default.AuditReplayEntriesTotal() }
func AuditRotationsTotal() uint64     { return Default.AuditRotationsTotal() }
func IncAuditBufferedDroppedToOverflow() {
	Default.IncAuditBufferedDroppedToOverflow()
}
func AddAuditBufferedDrainedFromOverflow(n uint64) {
	Default.AddAuditBufferedDrainedFromOverflow(n)
}
func SetAuditBufferedQueueDepth(n int64) { Default.SetAuditBufferedQueueDepth(n) }
func AuditBufferedDroppedToOverflowTotal() uint64 {
	return Default.AuditBufferedDroppedToOverflowTotal()
}
func AuditBufferedDrainedFromOverflowTotal() uint64 {
	return Default.AuditBufferedDrainedFromOverflowTotal()
}
func SetMigrationStatus(from, to, status string, value int64) {
	Default.SetMigrationStatus(from, to, status, value)
}
func MigrationStatusFor(from, to, status string) int64 {
	return Default.MigrationStatusFor(from, to, status)
}

// -- Notify / SSE / queue gauges --

func SetNotifyQueueDepth(n int) { Default.SetNotifyQueueDepth(n) }
func IncNotifySpooled()         { Default.IncNotifySpooled() }
func AddNotifyDespooled(n uint64) {
	Default.AddNotifyDespooled(n)
}
func NotifySpooledTotal() uint64   { return Default.NotifySpooledTotal() }
func NotifyDespooledTotal() uint64 { return Default.NotifyDespooledTotal() }
func ObserveNotifyDispatch(notifier string, seconds float64) {
	Default.ObserveNotifyDispatch(notifier, seconds)
}
func IncSSESubscribers()        { Default.IncSSESubscribers() }
func DecSSESubscribers()        { Default.DecSSESubscribers() }
func SetRateLimitBuckets(n int) { Default.SetRateLimitBuckets(n) }
func SetPendingApprovals(n int) { Default.SetPendingApprovals(n) }

// -- Hot-path duration histograms --

func ObserveRequestDuration(ms float64)    { Default.ObserveRequestDuration(ms) }
func ObservePolicyEvalDuration(ms float64) { Default.ObservePolicyEvalDuration(ms) }
func ObserveAuditWriteDuration(ms float64) { Default.ObserveAuditWriteDuration(ms) }

// -- Output --

// WritePrometheus writes the Default registry in Prometheus text format.
func WritePrometheus(w io.Writer) { Default.WritePrometheus(w) }
