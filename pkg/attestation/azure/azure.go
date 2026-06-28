// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package azure

type EnvConfig struct {
	OSBuild  string
	OSType   string
	OSDistro string
	MaaURL   string
}

func NewEnvConfigFromAgent(agentOSBuild, agentOSType, agentOSDistro, maaURL string) *EnvConfig {
	return &EnvConfig{
		OSBuild:  agentOSBuild,
		OSType:   agentOSType,
		OSDistro: agentOSDistro,
		MaaURL:   maaURL,
	}
}

func InitializeDefaultMAAVars(config *EnvConfig) {
	MaaURL = config.MaaURL
}

func (c *EnvConfig) InitializeOSVars(build, osType, osDistro string) {
	if build != "" {
		c.OSBuild = build
	}
	if osType != "" {
		c.OSType = osType
	}
	if osDistro != "" {
		c.OSDistro = osDistro
	}
}
