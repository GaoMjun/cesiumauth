package cesiumauth

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(CesiumAuth{})
}

var (
	DNS_SERVER = "114.114.114.114:53"

	dialer = net.Dialer{Resolver: &net.Resolver{Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return net.Dial(network, DNS_SERVER)
	}}}

	httpClient = &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (conn net.Conn, err error) {
				return dialer.Dial(network, addr)
			},
		},
		Timeout: time.Second * 3,
	}
)

type CesiumAuth struct {
	logger *zap.Logger

	Url string `json:"url"`

	authorization string
}

func (CesiumAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cesium_auth",
		New: func() caddy.Module { return new(CesiumAuth) },
	}
}

func (self *CesiumAuth) Provision(ctx caddy.Context) (err error) {
	self.logger = ctx.Logger(self)

	go func() {
		self.updateAuthorization(self.Url)

		for {
			<-time.After(time.Second * 60)
			self.updateAuthorization(self.Url)
		}
	}()
	return
}

func (self CesiumAuth) Validate() error {
	return nil
}

func (self *CesiumAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) (err error) {
	r.Header.Set("Authorization", "Bearer "+self.authorization)

	err = next.ServeHTTP(w, r)
	return
}

func (self *CesiumAuth) updateAuthorization(u string) {
	var (
		err  error
		resp *http.Response
		body []byte
		ep   = endpoint{}
	)

	if resp, err = httpClient.Get(u); err != nil {
		return
	}

	if body, err = ioutil.ReadAll(resp.Body); err != nil {
		return
	}

	if err = json.Unmarshal(body, &ep); err != nil {
		return
	}

	self.authorization = ep.AccessToken
}

type endpoint struct {
	AccessToken string `json:"accessToken"`
}
