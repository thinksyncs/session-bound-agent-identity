// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type healthResponse struct {
	Service  string `json:"service"`
	Instance string `json:"instance"`
	Status   string `json:"status"`
}

// MakeHandler registers the manager HTTP utility endpoints.
func MakeHandler(router *chi.Mux, serviceName, instanceID string) http.Handler {
	router.Get("/health", healthHandler(serviceName, instanceID))
	router.Handle("/metrics", promhttp.Handler())
	return router
}

func healthHandler(serviceName, instanceID string) http.HandlerFunc {
	response := healthResponse{
		Service:  serviceName,
		Instance: instanceID,
		Status:   "pass",
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/health+json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
	}
}
