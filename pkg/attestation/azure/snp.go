// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/edgelesssys/go-azguestattestation/maa"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-sev-guest/tools/lib/report"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"google.golang.org/protobuf/proto"
)

// TokenValidator defines the interface for Azure token validation.
type TokenValidator interface {
	Validate(token string) (map[string]any, error)
}

type azureTokenValidator struct{}

func (v *azureTokenValidator) Validate(token string) (map[string]any, error) {
	return validateToken(token)
}

var (
	MaaURL             = "https://sharedeus2.eus2.attest.azure.net"
	ErrFetchAzureToken = errors.New("failed to fetch Azure token")
)

var DefaultValidator TokenValidator = &azureTokenValidator{}

var (
	_ attestation.Provider = (*provider)(nil)
	_ attestation.Verifier = (*verifier)(nil)
)

type provider struct{}

func NewProvider() attestation.Provider {
	return provider{}
}

func (a provider) Attestation(teeNonce []byte, vTpmNonce []byte) ([]byte, error) {
	var tokenNonce [vtpm.Nonce]byte
	copy(tokenNonce[:], teeNonce)

	params, err := maa.NewParameters(context.Background(), tokenNonce[:], http.DefaultClient, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get report: %w", err)
	}

	snpReport, err := report.ParseAttestation(params.SNPReport, "bin")
	if err != nil {
		return nil, fmt.Errorf("failed to parse SNP report: %w", err)
	}

	quote, err := vtpm.FetchQuote(vTpmNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch quote: %w", err)
	}

	quote.TeeAttestation = &attest.Attestation_SevSnpAttestation{
		SevSnpAttestation: snpReport,
	}
	return proto.Marshal(quote)
}

func (a provider) TeeAttestation(teeNonce []byte) ([]byte, error) {
	var tokenNonce [vtpm.Nonce]byte
	copy(tokenNonce[:], teeNonce)

	params, err := maa.NewParameters(context.Background(), tokenNonce[:], http.DefaultClient, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get report: %w", err)
	}

	return params.SNPReport, nil
}

func (a provider) VTpmAttestation(vTpmNonce []byte) ([]byte, error) {
	quote, err := vtpm.FetchQuote(vTpmNonce)
	if err != nil {
		return []byte{}, errors.Wrap(vtpm.ErrFetchQuote, err)
	}

	return proto.Marshal(quote)
}

type MaaClient interface {
	Attest(ctx context.Context, nonce []byte, maaURL string, client *http.Client) (string, error)
}

type defaultMaaClient struct{}

func (c *defaultMaaClient) Attest(ctx context.Context, nonce []byte, maaURL string, client *http.Client) (string, error) {
	return maa.Attest(ctx, nonce, maaURL, client)
}

var DefaultMaaClient MaaClient = &defaultMaaClient{}

func (a provider) AzureAttestationToken(tokenNonce []byte) ([]byte, error) {
	token, err := DefaultMaaClient.Attest(context.Background(), tokenNonce, MaaURL, http.DefaultClient)
	if err != nil {
		return nil, errors.Wrap(ErrFetchAzureToken, err)
	}

	return []byte(token), nil
}

type verifier struct {
	writer io.Writer
}

func NewVerifier(writer io.Writer) attestation.Verifier {
	return verifier{
		writer: writer,
	}
}

// VerifyEAT verifies an EAT token and extracts the binary report for verification.
func (v verifier) VerifyEAT(eatToken []byte, teeNonce []byte, vTpmNonce []byte) error {
	// Kept only for backward compatibility with legacy call sites.
	// Current verification path uses VerifyWithCoRIM.
	return fmt.Errorf("VerifyEAT is deprecated, use VerifyWithCoRIM")
}

func (v verifier) VerifyWithCoRIM(report []byte, manifest *corim.UnsignedCorim) error {
	attestation := &attest.Attestation{}
	if err := proto.Unmarshal(report, attestation); err != nil {
		return fmt.Errorf("failed to unmarshal attestation report: %w", err)
	}

	// Extract measurement from SEV-SNP report if present
	snpRep := attestation.GetSevSnpAttestation()
	if snpRep == nil {
		return fmt.Errorf("no SEV-SNP attestation found in report")
	}

	measurement := snpRep.GetReport().GetMeasurement()
	if len(measurement) == 0 {
		return fmt.Errorf("no measurement in SEV-SNP report")
	}

	// Parse CoMID from CoRIM
	if len(manifest.Tags) == 0 {
		return fmt.Errorf("no tags in CoRIM")
	}

	for _, tag := range manifest.Tags {
		if !bytes.HasPrefix(tag, corim.ComidTag) {
			continue
		}

		tagValue := tag[len(corim.ComidTag):]

		var c comid.Comid
		if err := c.FromCBOR(tagValue); err != nil {
			return fmt.Errorf("failed to parse CoMID: %w", err)
		}

		// Match measurements
		if c.Triples.ReferenceValues != nil {
			for _, rv := range *c.Triples.ReferenceValues {
				if err := rv.Valid(); err != nil {
					continue
				}
				for _, m := range rv.Measurements {
					if m.Val.Digests == nil {
						continue
					}
					for _, digest := range *m.Val.Digests {
						if string(digest.HashValue) == string(measurement) {
							return nil // Match found
						}
					}
				}
			}
		}
	}

	return fmt.Errorf("no matching reference value found in CoRIM for Azure SEV-SNP")
}

func FetchAzureAttestationToken(tokenNonce []byte, maaURL string) ([]byte, error) {
	token, err := DefaultMaaClient.Attest(context.Background(), tokenNonce, maaURL, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("error fetching azure token: %w", err)
	}
	return []byte(token), nil
}

// AzureMeasurementData contains the exact fields extracted from an Azure attestation token
// needed to construct a CoRIM policy for the SNP platform.
type AzureMeasurementData struct {
	Measurement string
	HostData    string
	Policy      uint64
	SVN         uint64
}

// ExtractAzureMeasurement extracts the core SNP measurements from an Azure Attestation Token.
func ExtractAzureMeasurement(token string) (*AzureMeasurementData, error) {
	claims, err := DefaultValidator.Validate(token)
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	tee, ok := claims["x-ms-isolation-tee"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("failed to get tee from claims")
	}

	measurementString, ok := tee["x-ms-sevsnpvm-launchmeasurement"].(string)
	if !ok {
		return nil, fmt.Errorf("failed to get measurement from claims")
	}

	hostDataString, ok := tee["x-ms-sevsnpvm-hostdata"].(string)
	if !ok {
		// Host data is optional
		hostDataString = ""
	}

	guestSVNFloat, ok := tee["x-ms-sevsnpvm-guestsvn"].(float64)
	if !ok {
		return nil, fmt.Errorf("failed to get guest SVN from claims")
	}

	// We default the SNP policy to 0 if not provided, though typically Azure sets this
	// in x-ms-sevsnpvm-policy based on the guest. For now, we will return 0 and rely on
	// callers to provide the policy if they want to override.

	return &AzureMeasurementData{
		Measurement: measurementString,
		HostData:    hostDataString,
		SVN:         uint64(guestSVNFloat),
		Policy:      0, // The policy is usually passed externally in Azure's case, or decoded separately
	}, nil
}

func validateToken(token string) (map[string]any, error) {
	unverifiedToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	jku, jkuOk := unverifiedToken.Header["jku"].(string)
	if !jkuOk {
		return nil, fmt.Errorf("token is missing jku or kid in header")
	}
	if _, kidOk := unverifiedToken.Header["kid"].(string); !kidOk {
		return nil, fmt.Errorf("token is missing jku or kid in header")
	}
	maaURLCerts, err := validateJKU(jku, MaaURL)
	if err != nil {
		return nil, err
	}

	keySet, err := maa.GetKeySet(context.Background(), maaURLCerts, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get key set: %w", err)
	}

	claims, err := maa.ValidateToken(token, keySet)
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	return claims, nil
}

func validateJKU(jku, configuredMaaURL string) (string, error) {
	jkuURL, err := url.Parse(jku)
	if err != nil {
		return "", fmt.Errorf("invalid jku URL: %w", err)
	}
	if jkuURL.Scheme != "https" {
		return "", fmt.Errorf("jku must use https")
	}
	if jkuURL.Hostname() == "" || jkuURL.User != nil || jkuURL.RawQuery != "" || jkuURL.Fragment != "" {
		return "", fmt.Errorf("jku must be a clean absolute https URL without userinfo, query, or fragment")
	}
	if jkuURL.Path != "/certs" {
		return "", fmt.Errorf("jku path must be /certs")
	}

	// If MaaURL is explicitly configured, require host pinning to the same endpoint.
	if configuredMaaURL != "" {
		maaURL, err := url.Parse(configuredMaaURL)
		if err != nil {
			return "", fmt.Errorf("invalid configured MAA URL: %w", err)
		}
		if maaURL.Scheme != "https" || maaURL.Hostname() == "" {
			return "", fmt.Errorf("configured MAA URL must be an absolute https URL")
		}
		if !strings.EqualFold(jkuURL.Hostname(), maaURL.Hostname()) || jkuURL.Port() != maaURL.Port() {
			return "", fmt.Errorf("jku host %q does not match configured MAA host %q", jkuURL.Host, maaURL.Host)
		}
		return configuredMaaURL, nil
	}

	// When MaaURL is not configured, accept only official Azure attestation hosts.
	if !strings.HasSuffix(strings.ToLower(jkuURL.Hostname()), ".attest.azure.net") {
		return "", fmt.Errorf("jku host is not an allowed Azure attestation domain")
	}

	return (&url.URL{Scheme: jkuURL.Scheme, Host: jkuURL.Host}).String(), nil
}
