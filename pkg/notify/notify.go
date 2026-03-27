package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// Event describes something that happened in the system.
type Event struct {
	Type      string               `json:"type"` // "approval_required", "denied", "allowed"
	Timestamp time.Time            `json:"timestamp"`
	Request   policy.ActionRequest `json:"request"`
	Result    policy.CheckResult   `json:"result"`
	// ApprovalURL is set when Type == "approval_required".
	ApprovalURL string `json:"approval_url,omitempty"`
}

// Notifier delivers events to external systems.
type Notifier interface {
	Notify(event Event) error
}

// Dispatcher fans out events to multiple notifiers.
type Dispatcher struct {
	notifiers []Notifier
}

// NewDispatcher builds a dispatcher from the policy notification config.
func NewDispatcher(cfg policy.NotificationCfg) *Dispatcher {
	d := &Dispatcher{}

	for _, t := range cfg.ApprovalRequired {
		d.notifiers = append(d.notifiers, targetToNotifier(t, "approval_required"))
	}
	for _, t := range cfg.OnDeny {
		d.notifiers = append(d.notifiers, targetToNotifier(t, "denied"))
	}

	return d
}

func targetToNotifier(t policy.NotifyTarget, eventFilter string) Notifier {
	switch t.Type {
	case "webhook":
		return &WebhookNotifier{URL: t.URL, Filter: eventFilter}
	case "slack":
		return &SlackNotifier{WebhookURL: t.URL, Filter: eventFilter}
	case "console":
		return &ConsoleNotifier{Filter: eventFilter}
	case "log":
		return &LogNotifier{Level: t.Level, Filter: eventFilter}
	default:
		return &LogNotifier{Level: "warn", Filter: eventFilter}
	}
}

// Send dispatches an event to all matching notifiers. Errors are logged but
// do not stop delivery to other notifiers.
func (d *Dispatcher) Send(event Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	for _, n := range d.notifiers {
		if err := n.Notify(event); err != nil {
			log.Printf("notify error (%T): %v", n, err)
		}
	}
}

// --- Webhook ---

// WebhookNotifier posts JSON to an arbitrary URL.
type WebhookNotifier struct {
	URL    string
	Filter string // only fire for this event type ("" = all)
}

func (w *WebhookNotifier) Notify(event Event) error {
	if w.Filter != "" && w.Filter != event.Type {
		return nil
	}
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AgentGuard/1.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook POST %s: %w", w.URL, err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook %s returned %d", w.URL, resp.StatusCode)
	}
	return nil
}

// --- Slack ---

// SlackNotifier posts a formatted message to a Slack incoming webhook.
type SlackNotifier struct {
	WebhookURL string
	Filter     string
}

func (s *SlackNotifier) Notify(event Event) error {
	if s.Filter != "" && s.Filter != event.Type {
		return nil
	}

	emoji := ":white_check_mark:"
	color := "#36a64f"
	switch event.Type {
	case "denied":
		emoji = ":no_entry:"
		color = "#e01e5a"
	case "approval_required":
		emoji = ":warning:"
		color = "#ecb22e"
	}

	action := event.Request.Command
	if action == "" {
		action = event.Request.Path
	}
	if action == "" {
		action = event.Request.Domain
	}

	text := fmt.Sprintf("%s *%s* | scope: `%s` | action: `%s`\n>%s",
		emoji, event.Result.Decision, event.Request.Scope, action, event.Result.Reason)

	if event.ApprovalURL != "" {
		text += fmt.Sprintf("\n><%s|Approve this action>", event.ApprovalURL)
	}

	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color":     color,
				"text":      text,
				"footer":    "AgentGuard",
				"ts":        event.Timestamp.Unix(),
				"mrkdwn_in": []string{"text"},
			},
		},
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, s.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("slack POST: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack returned %d", resp.StatusCode)
	}
	return nil
}

// --- Console ---

// ConsoleNotifier prints events to stdout.
type ConsoleNotifier struct {
	Filter string
}

func (c *ConsoleNotifier) Notify(event Event) error {
	if c.Filter != "" && c.Filter != event.Type {
		return nil
	}
	action := event.Request.Command
	if action == "" {
		action = event.Request.Path
	}
	if action == "" {
		action = event.Request.Domain
	}

	fmt.Printf("[AgentGuard] %s | scope=%s action=%q agent=%s | %s\n",
		event.Result.Decision, event.Request.Scope, action,
		event.Request.AgentID, event.Result.Reason)

	if event.ApprovalURL != "" {
		fmt.Printf("  → Approve: %s\n", event.ApprovalURL)
	}
	return nil
}

// --- Log ---

// LogNotifier logs events via the standard logger.
type LogNotifier struct {
	Level  string
	Filter string
}

func (l *LogNotifier) Notify(event Event) error {
	if l.Filter != "" && l.Filter != event.Type {
		return nil
	}
	action := event.Request.Command
	if action == "" {
		action = event.Request.Path
	}
	if action == "" {
		action = event.Request.Domain
	}
	log.Printf("[%s] %s scope=%s action=%q agent=%s reason=%q",
		l.Level, event.Result.Decision, event.Request.Scope,
		action, event.Request.AgentID, event.Result.Reason)
	return nil
}
