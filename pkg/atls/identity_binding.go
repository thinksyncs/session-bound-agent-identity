// SPDX-License-Identifier: Apache-2.0

package atls

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"

	"github.com/thinksyncs/hardware-aware-tls-identity-binding/pkg/atls/ea"
	eaattestation "github.com/thinksyncs/hardware-aware-tls-identity-binding/pkg/atls/eaattestation"
	"github.com/thinksyncs/hardware-aware-tls-identity-binding/pkg/atls/identitypolicy"
	internaltransport "github.com/thinksyncs/hardware-aware-tls-identity-binding/pkg/atls/internal_transport"
)

// IdentityBindingFromConnectionState derives identity-policy binding values
// from the accepted TLS session and aTLS validation result.
func IdentityBindingFromConnectionState(st *tls.ConnectionState, validation *ea.ValidationResult) (identitypolicy.Binding, error) {
	binding, err := internaltransport.ExpectedIdentityBinding(validation)
	if err != nil {
		return identitypolicy.Binding{}, err
	}
	if st == nil {
		return identitypolicy.Binding{}, fmt.Errorf("atls: missing TLS connection state")
	}
	exported, _, err := eaattestation.ExportAttestationValue(st, eaattestation.ExporterLabelAttestation, validation.Context)
	if err != nil {
		return identitypolicy.Binding{}, err
	}
	exporterHash := sha256.Sum256(exported)
	binding.TLSExporterSHA256 = hex.EncodeToString(exporterHash[:])
	return binding, nil
}
