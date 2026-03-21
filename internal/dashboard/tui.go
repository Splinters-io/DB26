package dashboard

import (
	"fmt"
	"strings"
	"time"

	"db26/internal/correlate"
	"db26/internal/metrics"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("205")).
			Background(lipgloss.Color("235")).
			Padding(0, 1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("39"))

	countStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("82"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196"))

	viableStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("226"))

	authStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("208"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("242"))

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("240")).
			Padding(0, 1)
)

// LogEntry is an immutable log line for the live log panel.
type LogEntry struct {
	Time    time.Time
	Message string
}

// Model is the bubbletea model for the recruiter dashboard.
type Model struct {
	metrics    *metrics.Counters
	correlator *correlate.Correlator
	logs       []LogEntry
	maxLogs    int
	width      int
	height     int
	quitting   bool
}

// NewModel creates a new dashboard model.
func NewModel(m *metrics.Counters, corr *correlate.Correlator) Model {
	return Model{
		metrics:    m,
		correlator: corr,
		maxLogs:    20,
		width:      80,
		height:     24,
	}
}

// tickMsg triggers periodic refresh.
type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// AddLogMsg adds a log entry from outside the TUI loop.
type AddLogMsg LogEntry

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return tickCmd()
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tickMsg:
		return m, tickCmd()

	case AddLogMsg:
		entry := LogEntry(msg)
		m.logs = append(m.logs, entry)
		if len(m.logs) > m.maxLogs {
			// Keep only the most recent entries (immutable pattern)
			newLogs := make([]LogEntry, m.maxLogs)
			copy(newLogs, m.logs[len(m.logs)-m.maxLogs:])
			m.logs = newLogs
		}
	}

	return m, nil
}

// View implements tea.Model.
func (m Model) View() string {
	if m.quitting {
		return ""
	}

	snap := m.metrics.Snap()

	var b strings.Builder

	// Title bar
	elapsed := snap.Elapsed.Truncate(time.Second)
	title := titleStyle.Render(fmt.Sprintf(" DB26 Recruiter Dashboard                    [Running %s] ", elapsed))
	b.WriteString(title)
	b.WriteString("\n\n")

	// Probes panel
	probes := headerStyle.Render("PROBES") + "\n"
	probes += fmt.Sprintf("  Sent:     %s\n", countStyle.Render(fmt.Sprintf("%d", snap.ProbesSent)))
	probes += fmt.Sprintf("  HTTP OK:  %s\n", countStyle.Render(fmt.Sprintf("%d", snap.ProbesHTTPOK)))
	probes += fmt.Sprintf("  HTTPS OK: %s\n", countStyle.Render(fmt.Sprintf("%d", snap.ProbesHTTPSOK)))
	probes += fmt.Sprintf("  Errors:   %s\n", errorStyle.Render(fmt.Sprintf("%d", snap.ProbesErrors)))
	probes += fmt.Sprintf("  Rate:     %s", countStyle.Render(fmt.Sprintf("%.0f/s", snap.RPS)))

	// Callbacks panel
	callbacks := headerStyle.Render("CALLBACKS") + "\n"
	callbacks += fmt.Sprintf("  DNS:    %s\n", countStyle.Render(fmt.Sprintf("%d", snap.CallbackDNS)))
	callbacks += fmt.Sprintf("  HTTP:   %s\n", countStyle.Render(fmt.Sprintf("%d", snap.CallbackHTTP)))
	callbacks += fmt.Sprintf("  HTTPS:  %s\n", countStyle.Render(fmt.Sprintf("%d", snap.CallbackHTTPS)))
	callbacks += fmt.Sprintf("  Total:  %s", countStyle.Render(fmt.Sprintf("%d", snap.CallbackTotal)))

	// Side by side
	b.WriteString(sideBySide(boxStyle.Render(probes), boxStyle.Render(callbacks), m.width))
	b.WriteString("\n")

	// Viable domains
	results := m.correlator.Results()
	viableHeader := viableStyle.Render(fmt.Sprintf("VIABLE DOMAINS (%d)", len(results)))
	b.WriteString(viableHeader)
	b.WriteString("\n")

	maxShow := 8
	if len(results) < maxShow {
		maxShow = len(results)
	}
	for i := 0; i < maxShow; i++ {
		r := results[i]
		hdrs := strings.Join(r.Headers, ",")
		b.WriteString(fmt.Sprintf("  %s [%s]\n", r.Domain, dimStyle.Render(hdrs)))
	}
	if len(results) > 8 {
		b.WriteString(dimStyle.Render(fmt.Sprintf("  ... and %d more\n", len(results)-8)))
	}

	// Auth detections
	b.WriteString("\n")
	authHeader := authStyle.Render(fmt.Sprintf("AUTH DETECTIONS (%d)", snap.AuthTotal))
	b.WriteString(authHeader)
	b.WriteString("\n")
	if snap.AuthNTLM > 0 {
		b.WriteString(fmt.Sprintf("  NTLM:      %d\n", snap.AuthNTLM))
	}
	if snap.AuthBasic > 0 {
		b.WriteString(fmt.Sprintf("  Basic:     %d\n", snap.AuthBasic))
	}
	if snap.AuthNegotiate > 0 {
		b.WriteString(fmt.Sprintf("  Negotiate: %d\n", snap.AuthNegotiate))
	}

	// Live log
	b.WriteString("\n")
	b.WriteString(headerStyle.Render("LIVE LOG"))
	b.WriteString("\n")

	logStart := 0
	if len(m.logs) > 6 {
		logStart = len(m.logs) - 6
	}
	for i := logStart; i < len(m.logs); i++ {
		entry := m.logs[i]
		ts := entry.Time.Format("15:04:05")
		b.WriteString(fmt.Sprintf("  %s %s\n", dimStyle.Render(ts), entry.Message))
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("Press q to quit"))

	return b.String()
}

// sideBySide renders two blocks side by side.
func sideBySide(left, right string, totalWidth int) string {
	leftLines := strings.Split(left, "\n")
	rightLines := strings.Split(right, "\n")

	maxLeft := 0
	for _, l := range leftLines {
		if len(l) > maxLeft {
			maxLeft = len(l)
		}
	}

	// Pad to half width
	halfWidth := totalWidth/2 - 1
	if halfWidth < maxLeft+2 {
		halfWidth = maxLeft + 2
	}

	maxLines := len(leftLines)
	if len(rightLines) > maxLines {
		maxLines = len(rightLines)
	}

	var b strings.Builder
	for i := 0; i < maxLines; i++ {
		l := ""
		if i < len(leftLines) {
			l = leftLines[i]
		}
		r := ""
		if i < len(rightLines) {
			r = rightLines[i]
		}

		// Pad left column
		padding := halfWidth - len(l)
		if padding < 1 {
			padding = 1
		}
		b.WriteString(l)
		b.WriteString(strings.Repeat(" ", padding))
		b.WriteString(r)
		b.WriteString("\n")
	}

	return b.String()
}
