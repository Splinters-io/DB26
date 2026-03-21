package main

import (
	"fmt"
	"os"

	"db26/internal/correlate"
	"db26/internal/dashboard"
	"db26/internal/metrics"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	m := metrics.New()
	viableCh := make(chan correlate.DomainResult, 100)
	corr := correlate.NewCorrelator(viableCh, m)

	model := dashboard.NewModel(m, corr)

	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "dashboard error: %s\n", err)
		os.Exit(1)
	}
}
