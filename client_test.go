package acpclient

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBasePath(t *testing.T) {

	for _, tc := range []struct {
		title    string
		url      string
		tid      string
		sid      string
		vanityTp string
		isErr    bool
		basePath string
		tenantID string
		serverID string
	}{
		{
			title:    "Non-vanity domain",
			url:      "https://acp.local/default/system",
			tenantID: "default",
			serverID: "system",
		},
		{
			title:    "Non-vanity domain with base path",
			url:      "https://acp.local/base/default/system",
			basePath: "/base",
			tenantID: "default",
			serverID: "system",
		},
		{
			title:    "Tenant vanity domain",
			url:      "https://acp.local/system",
			tid:      "default",
			vanityTp: "tenant",
			tenantID: "default",
			serverID: "system",
		},
		{
			title:    "Tenant vanity domain with base path",
			url:      "https://acp.local/base/system",
			tid:      "default",
			vanityTp: "tenant",
			basePath: "/base",
			tenantID: "default",
			serverID: "system",
		},
		{
			title:    "Server vanity domain",
			url:      "https://system.acp.local",
			tid:      "default",
			sid:      "system",
			vanityTp: "server",
			tenantID: "default",
			serverID: "system",
		},
		{
			title:    "Server vanity domain with base path",
			url:      "https://system.acp.local/base",
			tid:      "default",
			sid:      "system",
			vanityTp: "server",
			basePath: "/base",
			tenantID: "default",
			serverID: "system",
		},
		// errors
		{
			title: "Tenant vanity domain without VanityDomainType",
			url:   "https://acp.local/system",
			isErr: true,
		},
		{
			title:    "Tenant vanity domain without configured TenantID",
			url:      "https://acp.local/system",
			vanityTp: "tenant",
			isErr:    true,
		},
		{
			title:    "Tenant vanity domain without configured ServerID",
			url:      "https://system.acp.local",
			tid:      "default",
			vanityTp: "server",
			isErr:    true,
		},
	} {
		url, err := url.Parse(tc.url)
		if err != nil {
			t.Error(err)
		}
		config := Config{
			IssuerURL:        url,
			ServerID:         tc.sid,
			TenantID:         tc.tid,
			VanityDomainType: tc.vanityTp,
		}
		client := Client{}
		err = client.configureBasePath(config)
		if tc.isErr {
			assert.NotNil(t, err, tc.title)
		} else {
			assert.Nil(t, err, tc.title)
			assert.Equal(t, tc.tenantID, client.TenantID, tc.title)
			assert.Equal(t, tc.serverID, client.ServerID, tc.title)
			assert.Equal(t, tc.basePath, client.BasePath, tc.title)
		}
	}
}

func TestAPIPrefix(t *testing.T) {

	for _, tc := range []struct {
		title    string
		basePath string
		tenantID string
		serverID string
		vanityTp string
		format   string
		prefix   string
	}{
		{
			title:    "Non-vanity domain /api/admin",
			tenantID: "default",
			serverID: "system",
			format:   "/api/admin/%s",
			prefix:   "/api/admin/default",
		},
		{
			title:    "Tenant domain /api/admin",
			vanityTp: "tenant",
			tenantID: "default",
			serverID: "system",
			format:   "/api/admin/%s",
			prefix:   "/api/admin",
		},
		{
			title:    "Server domain /api/admin",
			vanityTp: "server",
			tenantID: "default",
			serverID: "system",
			format:   "/api/admin/%s",
			prefix:   "/api/admin",
		},
		{
			title:    "Non-vanity domain /api/developer",
			tenantID: "default",
			serverID: "system",
			format:   "/api/developer/%s/%s",
			prefix:   "/api/developer/default/system",
		},
		{
			title:    "Tenant domain /api/developer",
			vanityTp: "tenant",
			tenantID: "default",
			serverID: "system",
			format:   "/api/developer/%s/%s",
			prefix:   "/api/developer/system",
		},
		{
			title:    "Server domain /api/developer",
			vanityTp: "server",
			tenantID: "default",
			serverID: "system",
			format:   "/api/developer/%s/%s",
			prefix:   "/api/developer",
		},
		{
			title:    "Non-vanity domain /api/system",
			tenantID: "default",
			serverID: "system",
			format:   "/api/system/%s",
			prefix:   "/api/system/default",
		},
		{
			title:    "Tenant domain /api/system",
			vanityTp: "tenant",
			tenantID: "default",
			serverID: "system",
			format:   "/api/system/%s",
			prefix:   "/api/system",
		},
		{
			title:    "Server domain /api/system",
			vanityTp: "server",
			tenantID: "default",
			serverID: "system",
			format:   "/api/system/%s",
			prefix:   "/api/system",
		},
		{
			title:    "Non-vanity domain common apis",
			tenantID: "default",
			serverID: "system",
			format:   "/%s/%s",
			prefix:   "/default/system",
		},
		{
			title:    "Tenant domain common apis",
			vanityTp: "tenant",
			tenantID: "default",
			serverID: "system",
			format:   "/%s/%s",
			prefix:   "/system",
		},
		{
			title:    "Server domain common apis",
			vanityTp: "server",
			tenantID: "default",
			serverID: "system",
			format:   "/%s/%s",
			prefix:   "",
		},
	} {
		client := Client{
			TenantID: tc.tenantID,
			ServerID: tc.serverID,
		}
		assert.Equal(t, tc.prefix, client.apiPathPrefix(tc.vanityTp, tc.format), tc.title)
	}
}
