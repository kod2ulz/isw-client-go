package client

import (
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kod2ulz/gostart/api"
	"github.com/kod2ulz/gostart/collections"
	"github.com/kod2ulz/gostart/http"
	"github.com/kod2ulz/gostart/logr"
	"github.com/kod2ulz/gostart/utils"
	"github.com/kod2ulz/interswitch-quickteller/sql/db"
	dbi "github.com/kod2ulz/interswitch-quickteller/sql/db/interswitch"
	"github.com/kod2ulz/interswitch-quickteller/stores"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

const (
	HEADER_TIMESTAMP           = "Timestamp"
	HEADER_TERMINAL_ID         = "TerminalId"
	HEADER_NONCE               = "Nonce"
	HEADER_SIGNATURE           = "Signature"
	HEADER_AUTHORIZATION       = "Authorization"
	HEADER_AUTHORIZATION_REALM = "InterswitchAuth"
	HEADER_ISO_8859_1          = "ISO-8859-1"
	HEADER_AUTH_TOKEN          = "AuthToken"
	HEADER_APP_VERSION         = "v1"
)

type PhoenixClientOption func(*Phoenix)

func WithPhoenixDB(dbx *db.SqlDB) PhoenixClientOption {
	return func(p *Phoenix) {
		p.db = dbx
	}
}

func WithPhoenixConfig(conf *PhoenixConfig) PhoenixClientOption {
	return func(p *Phoenix) {
		p.conf = conf
		p.minio = stores.Minio(p.log.Logger)
	}
}

func WithPhoenixCredentials(terminalId, clientId, clientSecret string) PhoenixClientOption {
	conf := NewPhoenixClientConfig()
	conf.TerminalID, conf.ClientID, conf.ClientSecret = terminalId, clientId, clientSecret
	return WithPhoenixConfig(conf)
}

func WithPhoenixHost(host string) PhoenixClientOption {
	return func(p *Phoenix) {
		if p.conf != nil {
			p.conf.Host = host
		}
	}
}

func PhoenixClient(ctx context.Context, log *logr.Logger, opts ...PhoenixClientOption) (out *Phoenix, err error) {
	out = &Phoenix{log: &phoenixLogger{Logger: log}}
	out.log.px = out
	if len(opts) == 0 {
		return
	}
	for i := range opts {
		opts[i](out)
	}
	if out.conf == nil {
		return nil, errors.Errorf("phoenix configuration not initialised")
	} else if out.minio == nil {
		return nil, errors.Errorf("phoenix storage not initialised")
	}
	err = out.init(ctx)
	return
}

type Phoenix struct {
	db          *db.SqlDB
	log         *phoenixLogger
	conf        *PhoenixConfig
	minio       *stores.MinioClient
	rsaPrivate  *RsaPrivateKey
	ecdhPrivate *EcdhPrivateKey
	headers     http.Headers
	location    *time.Location
	hostIP      string
}

func (p Phoenix) Config() PhoenixConfig {
	return *p.conf
}

func (p *Phoenix) init(ctx context.Context) (err error) {
	g, ctx := errgroup.WithContext(ctx)
	g.Go(p.loadIP)
	g.Go(p.loadHeaders)
	g.Go(p.loadLocation)
	g.Go(func() error { return p.loadRsaKey(ctx) })
	g.Go(func() error { return p.loadEcdhKey(ctx) })
	return g.Wait()
}

func (p *Phoenix) loadHeaders() (err error) {
	p.headers = http.Headers{}
	client64 := base64.StdEncoding.EncodeToString([]byte(p.conf.ClientID))
	authorization := fmt.Sprintf("%s %s", HEADER_AUTHORIZATION_REALM, client64)
	p.headers.Add(HEADER_AUTHORIZATION, authorization)
	return
}

func (p *Phoenix) loadLocation() (err error) {
	p.location, err = time.LoadLocation(p.conf.Timezone)
	return
}

func (p *Phoenix) loadIP() (err error) {
	var res *url.URL
	var ips collections.List[net.IP]
	p.log.Info("loading IP address of client host")
	if p.conf == nil {
		return errors.Errorf("host not initialised in config")
	} else if res, err = url.Parse(p.conf.Host); err != nil {
		return
	} else if ips, err = net.LookupIP(res.Host); err != nil {
		return errors.Wrapf(err, "failed to resolve host IP")
	} else if len(ips) == 0 {
		return errors.Errorf("no IP addresses match %s", res.Host)
	} else if p.hostIP = ips.Filter(func(i int, ip net.IP) bool {
		return !ip.IsPrivate()
	}).First().String(); p.hostIP == "" {
		candidates := collections.MapList(ips, func(ip net.IP) string { return ip.String() })
		return errors.Errorf("all matching candidates [%v] are private", candidates)
	} //todo: other restrictive checks
	return
}

func (p *Phoenix) loadRsaKey(ctx context.Context) (err error) {
	path := fmt.Sprintf("%s/%s", p.conf.StorageFolder, p.conf.StorageRsaPath)
	log := p.log.WithField("operation", "loadRsaKey")
	p.rsaPrivate, err = loadKey(ctx, log, Keys.Rsa, p.minio, p.conf.RsaBitSize, p.conf.StorageBucket, path)
	return
}

func (p *Phoenix) loadEcdhKey(ctx context.Context) (err error) {
	path := fmt.Sprintf("%s/%s", p.conf.StorageFolder, p.conf.StorageEcdhPath)
	log := p.log.WithField("operation", "loadEcdhKey")
	p.ecdhPrivate, err = loadKey(ctx, log, Keys.Ecdh, p.minio, nil, p.conf.StorageBucket, path)
	return
}

func (p *Phoenix) Rsa() Key {
	if p.rsaPrivate == nil {
		return nil
	}
	return p.rsaPrivate
}

func (p *Phoenix) Ecdh() Key {
	if p.ecdhPrivate == nil {
		return nil
	}
	return p.ecdhPrivate
}

func (p *Phoenix) authToken() string {
	return ""
}

func (p *Phoenix) auth(requestId uuid.UUID, method, _url, authToken string, params ...string) (out http.Headers, err error) {
	out = http.Headers{}
	var signature []byte
	timestamp := time.Now().Unix()
	noonce := strings.ReplaceAll(requestId.String(), "-", "")

	out.MergeHeaders(p.headers)
	out.Add(HEADER_NONCE, noonce)
	out.Add(HEADER_TIMESTAMP, fmt.Sprint(timestamp))

	encodedUrl := url.QueryEscape(_url)
	signCipher := fmt.Sprintf("%s&%s&%d&%s&%s&%s", method, encodedUrl, timestamp, noonce, p.conf.ClientID, p.conf.ClientSecret)
	if len(params) > 0 {
		signCipher = strings.Join(append([]string{signCipher}, params...), "&")
	}

	if p.rsaPrivate == nil {
		return out, errors.Errorf("required rsa private key not set")
	} else if signature, err = p.rsaPrivate.Sign(crypto.SHA256, signCipher); err != nil {
		return out, errors.Wrapf(err, "failed to generate signature of cipler using SHA256withRSA encryption")
	}
	out.Add(HEADER_SIGNATURE, base64.StdEncoding.EncodeToString(signature))

	if authToken != "" {
		if authToken, err = TerminalKey(p.conf.TerminalID).Sign(authToken); err != nil {
			return out, errors.Wrap(err, "failed to sign authToken using terminalId")
		}
	}
	out.Add(HEADER_AUTH_TOKEN, authToken)

	return
}

type Request interface {
	api.RequestParam
	Headers(ctx context.Context, names ...string) (out map[string]string)
}

type PhoenixResponse map[string]any

func RawRequest[P Request, R any](p *Phoenix, ctx context.Context, req P, endpoint Endpoint) (out R, er api.Error) {
	var err error
	var res api.Response[PhoenixResponse]
	var call dbi.InterswitchApiCall
	var resData PhoenixResponse
	var headers http.Headers
	var requestID = p.log.getRequestID(ctx)
	if headers, err = p.auth(
		requestID, endpoint.Method, endpoint.Uri, p.authToken()); err != nil {
		return out, api.ServiceError(errors.Wrapf(err, "failed to process auth headers"))
	}
	// headers.Merge(req.Headers(ctx, api.RequestID))
	if call, err = p.log.Request(ctx, requestID, endpoint.Method, endpoint.Url(p.conf.Host), req, headers.Values()); err != nil {
		return api.SqlQueryError(req, out, err)
	}
	client := http.Client[PhoenixResponse](p.log.Entry).BaseUrl(p.conf.Host).MergeHeaders(headers).Body(req)
	//todo: check that IP is still not private
	if res = client.Request(ctx, endpoint.Method, endpoint.Uri); res.HasError() {
		p.log.Response(ctx, call.RequestID, res.Code(), res.Error, res.Headers(), res.Cookies())
		return out, res.Error
	} else if err = res.ParseDataTo(&resData); err != nil {
		return out, serviceError[R](err, "failed to parse %T to %T", res.Data, out)
	}
	if _, err = p.log.Response(ctx, call.RequestID, res.Code(), res.Data, res.Headers(), res.Cookies()); err != nil {
		p.log.WithError(err).WithField("res", res).Error("failed to log response to db")
	}
	//todo: read response for errors before setting this
	utils.StructCopy(resData, &out)
	return
}

func serviceError[T any](err error, message string, args ...interface{}) api.Error {
	return api.GeneralError[T](errors.Wrapf(err, message, args...)).
		WithError(errors.New("encountered error generating payment response")).
		WithErrorCode(api.ErrorCodeServiceError)
}
