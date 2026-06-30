// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package qemu

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const SEVSNPHostDataHexLength = 64

var (
	ErrMissingSEVSNPAppraisalValue = errors.New("missing SEV-SNP appraisal value")
	ErrSEVSNPAppraisalMismatch     = errors.New("SEV-SNP appraisal mismatch")
)

type SEVSNPAppraisalContract struct {
	RequireHostData     bool
	ExpectedHostData    string
	RequireKernelHashes bool
}

type SEVSNPAppraisalEvidence struct {
	HostData            string
	KernelHashesEnabled bool
}

// NormalizeSEVSNPHostData validates and normalizes a SEV-SNP HostData value.
func NormalizeSEVSNPHostData(hostData string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(hostData))
	if len(normalized) != SEVSNPHostDataHexLength {
		return "", fmt.Errorf("invalid SEV-SNP host data: expected %d hex characters", SEVSNPHostDataHexLength)
	}
	decoded, err := hex.DecodeString(normalized)
	if err != nil {
		return "", fmt.Errorf("invalid SEV-SNP host data: %w", err)
	}
	if len(decoded) != 32 {
		return "", fmt.Errorf("invalid SEV-SNP host data: expected 32 bytes")
	}
	return normalized, nil
}

func (contract SEVSNPAppraisalContract) Validate(evidence SEVSNPAppraisalEvidence) error {
	if contract.RequireHostData {
		if strings.TrimSpace(contract.ExpectedHostData) == "" {
			return fmt.Errorf("expected host data: %w", ErrMissingSEVSNPAppraisalValue)
		}
		expected, err := NormalizeSEVSNPHostData(contract.ExpectedHostData)
		if err != nil {
			return fmt.Errorf("expected host data: %w", err)
		}
		if strings.TrimSpace(evidence.HostData) == "" {
			return fmt.Errorf("observed host data: %w", ErrMissingSEVSNPAppraisalValue)
		}
		observed, err := NormalizeSEVSNPHostData(evidence.HostData)
		if err != nil {
			return fmt.Errorf("observed host data: %w", err)
		}
		if observed != expected {
			return fmt.Errorf("host data: %w", ErrSEVSNPAppraisalMismatch)
		}
	}
	if contract.RequireKernelHashes && !evidence.KernelHashesEnabled {
		return fmt.Errorf("kernel hashes: %w", ErrSEVSNPAppraisalMismatch)
	}
	return nil
}

func (config Config) ValidateSecurity() error {
	if config.SEVSNPConfig.EnableHostData && !config.EnableSEVSNP {
		return fmt.Errorf("SEV-SNP host data is enabled while SEV-SNP is disabled")
	}
	if config.EnableSEVSNP && config.SEVSNPConfig.EnableHostData {
		_, err := NormalizeSEVSNPHostData(config.SEVSNPConfig.HostData)
		return err
	}
	return nil
}

func (config Config) ConstructQemuArgsChecked() ([]string, error) {
	if err := config.ValidateSecurity(); err != nil {
		return nil, err
	}
	return config.ConstructQemuArgs(), nil
}
