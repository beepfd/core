package meta

import "regexp"

var (
	VerificationTimeRegexp           = regexp.MustCompile(`verification time\s+(?P<time>\d+) usec\n`)
	StackUsageRegexp                 = regexp.MustCompile(`stack depth\s+(?P<usage>\d+).*\n`)
	InstructionsProcessedRegexp      = regexp.MustCompile(`processed (?P<processed>\d+) insns`)
	InstructionsProcessedLimitRegexp = regexp.MustCompile(`\(limit (?P<limit>\d+)\)`)
	MaxStatesPerInstructionRegexp    = regexp.MustCompile(`max_states_per_insn (?P<max_states>\d+)`)
	TotalStatesRegexp                = regexp.MustCompile(`total_states (?P<total_states>\d+)`)
	PeakStatesRegexp                 = regexp.MustCompile(`peak_states (?P<peak_states>\d+)`)
)

type VerifierStats struct {
	VerificationTime           int `json:"verification_time"`
	StackDepth                 int `json:"stack_usage"`
	InstructionsProcessed      int `json:"instruction_processed"`
	InstructionsProcessedLimit int `json:"limit"`
	MaxStatesPerInstruction    int `json:"max_states_per_insn"`
	TotalStates                int `json:"total_states"`
	PeakStates                 int `json:"peak_states"`
}

type FieldConfig struct {
	Regexp        *regexp.Regexp
	KernelVersion string
	Setter        func(*VerifierStats, int)
}

var VerifierStatsConfigs = map[string]FieldConfig{
	"VerificationTime": {
		Regexp:        VerificationTimeRegexp,
		KernelVersion: "4.15",
		Setter:        func(s *VerifierStats, val int) { s.VerificationTime = val },
	},
	"StackDepth": {
		Regexp:        StackUsageRegexp,
		KernelVersion: "4.15",
		Setter:        func(s *VerifierStats, val int) { s.StackDepth = val },
	},
	"InstructionsProcessed": {
		Regexp:        InstructionsProcessedRegexp,
		KernelVersion: "4.15",
		Setter:        func(s *VerifierStats, val int) { s.InstructionsProcessed = val },
	},
	"InstructionsProcessedLimit": {
		Regexp:        InstructionsProcessedLimitRegexp,
		KernelVersion: "4.15",
		Setter:        func(s *VerifierStats, val int) { s.InstructionsProcessedLimit = val },
	},
	"MaxStatesPerInstruction": {
		Regexp:        MaxStatesPerInstructionRegexp,
		KernelVersion: "5.2",
		Setter:        func(s *VerifierStats, val int) { s.MaxStatesPerInstruction = val },
	},
	"TotalStates": {
		Regexp:        TotalStatesRegexp,
		KernelVersion: "5.2",
		Setter:        func(s *VerifierStats, val int) { s.TotalStates = val },
	},
	"PeakStates": {
		Regexp:        PeakStatesRegexp,
		KernelVersion: "5.2",
		Setter:        func(s *VerifierStats, val int) { s.PeakStates = val },
	},
}
