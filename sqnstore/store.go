package sqnstore

import (
	"fmt"
	"strconv"
	"time"
)

const (
	IndBits   = 5
	ArraySize = 1 << IndBits
	SQNHexLen = 12
	MaxSQN    = (1 << 48) - 1
	MaxSeq    = MaxSQN >> IndBits
)

// SubscriberState holds the per-IMSI SQN state tracked by the tool.
type SubscriberState struct {
	SeqMS     [ArraySize]uint64
	SQNMS     uint64
	UpdatedAt time.Time
}

// SplitSQN breaks SQN into SEQ and IND (lower 5 bits).
func SplitSQN(sqn uint64) (uint64, uint8, error) {
	if sqn > MaxSQN {
		return 0, 0, fmt.Errorf("sqnstore: sqn exceeds 48 bits: %x", sqn)
	}
	ind := uint8(sqn & ((1 << IndBits) - 1))
	seq := sqn >> IndBits
	return seq, ind, nil
}

// CombineSQN combines SEQ and IND into a 48-bit SQN.
func CombineSQN(seq uint64, ind uint8) (uint64, error) {
	if int(ind) >= ArraySize {
		return 0, fmt.Errorf("sqnstore: ind out of range: %d", ind)
	}
	if seq > MaxSeq {
		return 0, fmt.Errorf("sqnstore: seq out of range: %d", seq)
	}
	sqn := (seq << IndBits) | uint64(ind)
	return sqn, nil
}

// AcceptSQN applies freshness rules and updates the state when accepted.
func (s *SubscriberState) AcceptSQN(sqn uint64) (bool, error) {
	seq, ind, err := SplitSQN(sqn)
	if err != nil {
		return false, err
	}
	if seq > s.SeqMS[ind] {
		s.SeqMS[ind] = seq
		if sqn > s.SQNMS {
			s.SQNMS = sqn
		}
		return true, nil
	}
	return false, nil
}

// ParseSQNHex parses a 12-hex-digit SQN string.
func ParseSQNHex(s string) (uint64, error) {
	if len(s) != SQNHexLen {
		return 0, fmt.Errorf("sqnstore: sqn hex length must be %d: %q", SQNHexLen, s)
	}
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("sqnstore: invalid sqn hex %q: %w", s, err)
	}
	if v > MaxSQN {
		return 0, fmt.Errorf("sqnstore: sqn exceeds 48 bits: %x", v)
	}
	return v, nil
}

// FormatSQNHex returns a zero-padded 12-hex-digit SQN string.
func FormatSQNHex(sqn uint64) (string, error) {
	if sqn > MaxSQN {
		return "", fmt.Errorf("sqnstore: sqn exceeds 48 bits: %x", sqn)
	}
	return fmt.Sprintf("%012x", sqn), nil
}
