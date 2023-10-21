package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	_http "net/http"
	"net/url"

	"github.com/kod2ulz/gostart/api"
	"github.com/kod2ulz/gostart/collections"
	"github.com/kod2ulz/gostart/http"
	"github.com/kod2ulz/gostart/logr"
	"github.com/kod2ulz/gostart/utils"
	"github.com/kod2ulz/interswitch-quickteller/sql/db"
	dbi "github.com/kod2ulz/interswitch-quickteller/sql/db/interswitch"
	"github.com/kod2ulz/interswitch-quickteller/stores"
	"github.com/minio/minio-go/v7"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
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
	hostIP      string
}

func (p Phoenix) Config() PhoenixConfig {
	return *p.conf
}

func (p *Phoenix) init(ctx context.Context) (err error) {
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return p.loadRsaKey(ctx) })
	g.Go(func() error { return p.loadEcdhKey(ctx) })
	g.Go(p.loadIP)
	return g.Wait()
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
	log.Debug("loading from storage")
	if err = p.minio.StreamObject(ctx, p.conf.StorageBucket, path, func(i int64, s string, reader io.ReadCloser) (e error) {
		defer reader.Close()
		p.rsaPrivate, e = RsaPemDecode(reader)
		return
	}); err == nil {
		log.Info("loaded from storage")
		return
	} else if p.rsaPrivate, err = GenerateRsaKey(p.conf.RsaBitSize); err != nil {
		err = errors.Wrap(err, "failed to generate rsa key")
		log.WithError(err).Error("failed")
		return
	}
	return p.savePemKeyToStorage(ctx, log, p.rsaPrivate.Pem(), path)
}

func (p *Phoenix) loadEcdhKey(ctx context.Context) (err error) {
	path := fmt.Sprintf("%s/%s", p.conf.StorageFolder, p.conf.StorageEcdhPath)
	log := p.log.WithField("operation", "loadEcdhKey")
	log.Debug("loading from storage")
	if err = p.minio.StreamObject(ctx, p.conf.StorageBucket, path, func(i int64, s string, reader io.ReadCloser) (e error) {
		defer reader.Close()
		p.ecdhPrivate, e = EcdhPemDecode(reader)
		log.Info("loaded from storage")
		return
	}); err == nil {
		return
	} else if p.ecdhPrivate, err = GenerateEcdhKey(); err != nil {
		err = errors.Wrap(err, "failed to generate ecdh key")
		log.WithError(err).Error("failed")
		return
	}
	return p.savePemKeyToStorage(ctx, log, p.ecdhPrivate.Pem(), path)
}

func (p *Phoenix) savePemKeyToStorage(ctx context.Context, log *logrus.Entry, keyData []byte, path string) (err error) {
	size := int64(len(keyData))
	opts := minio.PutObjectOptions{
		ContentType: "application/x-pem-file",
	}
	if _, err = p.minio.PutObject(ctx, p.conf.StorageBucket, path, bytes.NewReader(keyData), size, opts); err != nil {
		err = errors.Wrapf(err, "failed to upload generated %s key to minio", path)
		log.WithError(err).Error("failed")
	}
	return
}

func (p *Phoenix) RsaPublic64() string {
	if p.rsaPrivate == nil {
		return ""
	}
	return p.rsaPrivate.PublicBase64()
}

func (p *Phoenix) EcdhPublic64() string {
	if p.ecdhPrivate == nil {
		return ""
	}
	return p.ecdhPrivate.PublicBase64()
}

type Request interface {
	api.RequestParam
	Headers(ctx context.Context, names ...string) (out map[string]string)
}

type PhxResponse map[string]any

func RawRequest[P Request, R any](p *Phoenix, ctx context.Context, req P, method, path string) (out R, er api.Error) {
	var err error
	var res api.Response[PhxResponse]
	var call dbi.InterswitchApiCall
	var resData PhxResponse
	var headers = req.Headers(ctx, api.RequestID)
	// headers["Content-Type"] = "application/json"
	// headers["content-type"] = "application/json"
	logHeaders := collections.ConvertMap(headers, func(k, v string) (string, []string) {
		return k, []string{v}
	})
	if call, err = p.log.Request(ctx, method, fmt.Sprintf("%s/%s", p.conf.Host, path), req, logHeaders); err != nil {
		return api.SqlQueryError(req, out, err)
	}
	client := http.Client[PhxResponse](p.log.Entry).BaseUrl(p.conf.Host).Headers(headers).Body(req)
	switch method {
	case _http.MethodPost:
		res = client.Post(ctx, path)
	case _http.MethodGet:
		res = client.Get(ctx, path)
	case _http.MethodPut:
		res = client.Put(ctx, path)
	case _http.MethodDelete:
		res = client.Delete(ctx, path)
	default:
		return out, api.ServiceError(errors.Errorf("unsupported method %s", method))
	}
	if res.HasError() {
		p.log.Response(ctx, call.RequestID, res.Code(), res.Error, res.Headers(), res.Cookies())
		return out, res.Error
	} else if err = res.ParseDataTo(&resData); err != nil {
		return out, serviceError[R](err, "failed to parse %T to %T", res.Data, out)
	}
	if _, err = p.log.Response(ctx, call.RequestID, res.Code(), res.Data, res.Headers(), res.Cookies()); err != nil {
		p.log.WithError(err).WithField("res", res).Error("failed to log response to db")
	}
	utils.StructCopy(resData, &out)
	return
}

func serviceError[T any](err error, message string, args ...interface{}) api.Error {
	return api.GeneralError[T](errors.Wrapf(err, message, args...)).
		WithError(errors.New("encountered error generating payment response")).
		WithErrorCode(api.ErrorCodeServiceError)
}
