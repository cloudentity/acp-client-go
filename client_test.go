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
		rtgMode  string
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
			rtgMode:  "tenant",
			tenantID: "default",
			serverID: "system",
		},
		{
			title:    "Tenant vanity domain with base path",
			url:      "https://acp.local/base/system",
			tid:      "default",
			rtgMode:  "tenant",
			basePath: "/base",
			tenantID: "default",
			serverID: "system",
		},
		{
			title:    "Server vanity domain",
			url:      "https://system.acp.local",
			tid:      "default",
			sid:      "system",
			rtgMode:  "server",
			tenantID: "default",
			serverID: "system",
		},
		{
			title:    "Server vanity domain with base path",
			url:      "https://system.acp.local/base",
			tid:      "default",
			sid:      "system",
			rtgMode:  "server",
			basePath: "/base",
			tenantID: "default",
			serverID: "system",
		},
		// errors
		{
			title: "Tenant vanity domain without RoutingMode",
			url:   "https://acp.local/system",
			isErr: true,
		},
		{
			title:   "Tenant vanity domain without configured TenantID",
			url:     "https://acp.local/system",
			rtgMode: "tenant",
			isErr:   true,
		},
		{
			title:   "Tenant vanity domain without configured ServerID",
			url:     "https://system.acp.local",
			tid:     "default",
			rtgMode: "server",
			isErr:   true,
		},
	} {
		url, err := url.Parse(tc.url)
		if err != nil {
			t.Error(err)
		}
		config := Config{
			IssuerURL:   url,
			RoutingMode: tc.rtgMode,
			TenantID:    tc.tid,
			ServerID:    tc.sid,
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
		rtgMode  string
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
			rtgMode:  "tenant",
			tenantID: "default",
			serverID: "system",
			format:   "/api/admin/%s",
			prefix:   "/api/admin",
		},
		{
			title:    "Server domain /api/admin",
			rtgMode:  "server",
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
			rtgMode:  "tenant",
			tenantID: "default",
			serverID: "system",
			format:   "/api/developer/%s/%s",
			prefix:   "/api/developer/system",
		},
		{
			title:    "Server domain /api/developer",
			rtgMode:  "server",
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
			rtgMode:  "tenant",
			tenantID: "default",
			serverID: "system",
			format:   "/api/system/%s",
			prefix:   "/api/system",
		},
		{
			title:    "Server domain /api/system",
			rtgMode:  "server",
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
			rtgMode:  "tenant",
			tenantID: "default",
			serverID: "system",
			format:   "/%s/%s",
			prefix:   "/system",
		},
		{
			title:    "Server domain common apis",
			rtgMode:  "server",
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
		assert.Equal(t, tc.prefix, client.apiPathPrefix(tc.rtgMode, tc.format), tc.title)
	}
}
