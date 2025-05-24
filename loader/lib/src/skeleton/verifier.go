package skeleton

import (
	"strconv"

	"github.com/cen-ngc5139/BeePF/loader/lib/src/meta"
)

type Verifier struct {
	RawStats      string
	VerifierStats meta.VerifierStats
}

func NewVerifier(rawStats string) *Verifier {
	return &Verifier{
		RawStats: rawStats,
	}
}

func (v *Verifier) ParseOutput() error {
	for _, config := range meta.VerifierStatsConfigs {
		match := config.Regexp.FindStringSubmatch(v.RawStats)
		if len(match) == 0 {
			continue
		}

		if val, err := strconv.Atoi(match[1]); err == nil {
			config.Setter(&v.VerifierStats, val)
		}
	}
	return nil
}
