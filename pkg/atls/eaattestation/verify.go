// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
)

type EvidenceVerifier interface {
	VerifyEvidence(evidence []byte, binding EvidenceBinding) error
}

type ResultsVerifier interface {
	VerifyAttestationResults(results []byte, binding EvidenceBinding) error
}

type VerificationPolicy struct {
	EvidenceVerifier EvidenceVerifier
	ResultsVerifier  ResultsVerifier
}

func (p VerificationPolicy) RequiresAttestation() bool {
	return p.EvidenceVerifier != nil || p.ResultsVerifier != nil
}

func VerifyPayload(st *tls.ConnectionState, defaultLabel string, certificateRequestContext []byte, leaf *x509.Certificate, payload *Payload, policy VerificationPolicy) (*VerifiedPayload, error) {
	if err := payload.Validate(); err != nil {
		return nil, err
	}
	if err := payload.VerifyExporterLabel(defaultLabel); err != nil {
		return nil, err
	}

	verified := &VerifiedPayload{
		Payload:           payload,
		UsedExporterLabel: defaultLabel,
	}

	exportedValue, aikPubHash, binding, err := ComputeBinding(st, verified.UsedExporterLabel, certificateRequestContext, leaf)
	if err != nil {
		return nil, err
	}
	if err := verifyBinderValues(aikPubHash, binding, payload.Binder); err != nil {
		return nil, err
	}
	verified.BindingVerified = true

	reportData := sha512.Sum512(binding)
	nonce := sha256.Sum256(exportedValue)
	expectedBinding := EvidenceBinding{
		ReportData:    reportData,
		Nonce:         nonce,
		Binding:       append([]byte(nil), binding...),
		ExportedValue: append([]byte(nil), exportedValue...),
	}
	verified.Binding = expectedBinding
	if len(payload.Evidence) > 0 && policy.EvidenceVerifier != nil {
		if err := policy.EvidenceVerifier.VerifyEvidence(payload.Evidence, expectedBinding); err != nil {
			return nil, err
		}
		verified.EvidenceVerified = true
	} else if len(payload.Evidence) > 0 {
		return nil, ErrEvidenceVerificationMissing
	}
	if len(payload.AttestationResults) > 0 && policy.ResultsVerifier != nil {
		if err := policy.ResultsVerifier.VerifyAttestationResults(payload.AttestationResults, expectedBinding); err != nil {
			return nil, err
		}
		verified.ResultsVerified = true
	} else if len(payload.AttestationResults) > 0 {
		return nil, ErrResultsVerificationMissing
	}
	return verified, nil
}

func VerifyBinder(st *tls.ConnectionState, label string, certificateRequestContext []byte, leaf *x509.Certificate, binder AttestationBinder) error {
	_, aikPubHash, binding, err := ComputeBinding(st, label, certificateRequestContext, leaf)
	if err != nil {
		return err
	}
	return verifyBinderValues(aikPubHash, binding, binder)
}

func verifyBinderValues(aikPubHash, binding []byte, binder AttestationBinder) error {
	if !equalBytes(aikPubHash, binder.AIKPubHash) {
		return ErrAIKPubHashMismatch
	}
	if !equalBytes(binding, binder.Binding) {
		return ErrBindingMismatch
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
