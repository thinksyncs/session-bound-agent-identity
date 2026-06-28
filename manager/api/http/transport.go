// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(r *chi.Mux, svcName, instanceID string) http.Handler {
	r.Get("/health", health(svcName, instanceID))
	r.Handle("/metrics", promhttp.Handler())

	return r
}

func health(svcName, instanceID string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/health+json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"service":  svcName,
			"instance": instanceID,
			"status":   "pass",
		})
	}
}
