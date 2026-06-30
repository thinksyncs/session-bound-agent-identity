// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package qemu

import (
	"errors"
	"strings"
	"testing"
)

func TestSEVSNPAppraisalContractValidateAcceptsRequiredEvidence(t *testing.T) {
	hostData := strings.Repeat("a", SEVSNPHostDataHexLength)
	contract := SEVSNPAppraisalContract{
		RequireHostData:     true,
		ExpectedHostData:    strings.ToUpper(hostData),
		RequireKernelHashes: true,
	}
	evidence := SEVSNPAppraisalEvidence{
		HostData:            hostData,
		KernelHashesEnabled: true,
	}

	if err := contract.Validate(evidence); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestSEVSNPAppraisalContractValidateRejectsMissingExpectedHostData(t *testing.T) {
	contract := SEVSNPAppraisalContract{RequireHostData: true}

	err := contract.Validate(SEVSNPAppraisalEvidence{
		HostData: strings.Repeat("a", SEVSNPHostDataHexLength),
	})
	if !errors.Is(err, ErrMissingSEVSNPAppraisalValue) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingSEVSNPAppraisalValue)
	}
}

func TestSEVSNPAppraisalContractValidateRejectsMismatchedHostData(t *testing.T) {
	contract := SEVSNPAppraisalContract{
		RequireHostData:  true,
		ExpectedHostData: strings.Repeat("a", SEVSNPHostDataHexLength),
	}

	err := contract.Validate(SEVSNPAppraisalEvidence{
		HostData: strings.Repeat("b", SEVSNPHostDataHexLength),
	})
	if !errors.Is(err, ErrSEVSNPAppraisalMismatch) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrSEVSNPAppraisalMismatch)
	}
}

func TestSEVSNPAppraisalContractValidateRejectsMissingKernelHashes(t *testing.T) {
	contract := SEVSNPAppraisalContract{RequireKernelHashes: true}

	err := contract.Validate(SEVSNPAppraisalEvidence{})
	if !errors.Is(err, ErrSEVSNPAppraisalMismatch) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrSEVSNPAppraisalMismatch)
	}
}
