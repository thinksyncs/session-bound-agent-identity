// Copyright (c) 2026 ToppyMicroServices OU
// SPDX-License-Identifier: Apache-2.0

package qemu

import (
	"encoding/hex"
	"fmt"
	"strings"
)

const SEVSNPHostDataHexLength = 64

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
