package acpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"github.com/cloudentity/acp-client-go/clients/system/models"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/tools/go/analysis/passes/defers"
)

const (
	ErrorInvalidAccessToken = "invalid_access_token"
)

type Authenticator struct {
	transport *http.Client

	client *http.Client
	config clientcredentials.Config

	mutex sync.Mutex
}

func NewAuthenticator(config clientcredentials.Config, client *http.Client) *http.Client {
	return &http.Client{
		Transport: &Authenticator{
			transport: config.Client(context.WithValue(context.Background(), oauth2.HTTPClient, client)),
			config:    config,
			client:    client,
		},
	}
}

func (t *Authenticator) RoundTrip(req *http.Request) (res *http.Response, err error) {
	var (
		reqBuf bytes.Buffer
		reader = io.TeeReader(req.Body, &reqBuf)
	)

	defer req.Body.Close()
	req.Body = io.NopCloser(reader)

	
	if res, err = t.transport.Do(req); err != nil {
		return res, err
	} 

	if res.StatusCode == http.StatusUnauthorized {
		var (
			resBuf bytes.Buffer
			reader = io.TeeReader(res.Body, &resBuf)
			decoder = json.NewDecoder(reader)
			merr = &models.Error{}
		)
		
		if err = decoder.Decode(merr); err != nil {
			return res, err
		}

		if merr.ErrorCode == ErrorInvalidAccessToken {
			t.renew()
			req.Body = io.NopCloser(&reqBuf)
			return t.transport.Do(req)	
		}
	}

	return res, nil
}

func (t *Authenticator) renew() {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.transport = t.config.Client(context.WithValue(context.Background(), oauth2.HTTPClient, t.client))
}
