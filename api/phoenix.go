package api

import (
	"context"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/kod2ulz/gostart/api"
	"github.com/kod2ulz/gostart/logr"
	"github.com/kod2ulz/interswitch-quickteller/client"
	"github.com/pkg/errors"
)

type PhoenixApi interface {
	PhoenixClientApi
}

type PhoenixClientApi interface {
	ClientRegistration(context.Context) (ClientRegistrationResponse, api.Error)
	CompleteClientRegistration(context.Context) (ClientResponse, api.Error)
}

type PhoenixApiOption func(*phoenix)

func WithPhoenixClientConfig(conf *client.PhoenixConfig) PhoenixApiOption {
	return func(p *phoenix) {
		var err error
		if p.client, err = client.PhoenixClient(p.ctx, p.log, client.WithPhoenixConfig(conf)); err != nil {
			p.log.WithError(err).Fatal("failed to initialise phoenix client using config")
		}
	}
}

func WithPhoenixClient(client *client.Phoenix) PhoenixApiOption {
	return func(p *phoenix) {
		p.client = client
	}
}

type phoenix struct {
	client *client.Phoenix
	ctx    context.Context
	log    *logr.Logger
}

func Phoenix(ctx context.Context, log *logr.Logger, opts ...PhoenixApiOption) (out *phoenix, err error) {
	out = &phoenix{log: log, ctx: ctx}
	if len(opts) == 0 {
		return
	}
	for i := range opts {
		opts[i](out)
	}
	if out.client == nil {
		return nil, errors.Errorf("client not initialised")
	}
	return
}

func getRequestID(ctx context.Context) (out uuid.UUID) {
	var ok bool
	var err error
	if val := ctx.Value(api.RequestID); val != nil {
		if out, ok = val.(uuid.UUID); !ok {
			out = uuid.New()
		} else if out, err = uuid.Parse(fmt.Sprint(val)); err != nil {
			out = uuid.New()
		}
	}

	if out == uuid.Nil {
		out = uuid.New()
	}

	if _, ok := ctx.(*gin.Context); ok {
		ctx.(*gin.Context).Set(api.RequestID, out)
	}

	return uuid.New()
}

func getContextWithRequestID(ctx context.Context, requestId ...uuid.UUID) context.Context {
	if len(requestId) > 0 && requestId[0] != uuid.Nil {
		return context.WithValue(ctx, api.RequestID, requestId[0])
	}
	return context.WithValue(ctx, api.RequestID, getRequestID(ctx))
}
