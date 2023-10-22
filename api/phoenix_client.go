package api

import (
	"context"
	"net/http"

	"github.com/kod2ulz/gostart/api"
	"github.com/kod2ulz/interswitch-quickteller/client"
)

const (
	phoenixPostClientRegistration         = "api/v1/phoenix/client/clientRegistration"
	phoenixPostCompleteClientRegistration = "api/v1/phoenix/client/completeClientRegistration"
)

func (s *phoenix) ClientRegistration(ctx context.Context) (out ClientRegistrationResponse, er api.Error) {
	var err error
	var param ClientRegistrationRequest
	if err = param.FromContext(ctx, &param); err != nil {
		return out, api.RequestLoadError[ClientRegistrationRequest](err)
	} else if err = param.LoadPhoenixParams(s.client); err != nil {
		return out, api.ServiceError(err)
	} 
	return client.RawRequest[ClientRegistrationRequest, ClientRegistrationResponse](s.client, ctx, param, http.MethodPost, phoenixPostClientRegistration)
}
