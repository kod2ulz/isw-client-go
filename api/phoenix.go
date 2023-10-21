package api

import (
	"context"

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
	log    *logr.Logger
	ctx    context.Context
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
