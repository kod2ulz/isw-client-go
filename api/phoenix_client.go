package api

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/kod2ulz/gostart/api"
	"github.com/kod2ulz/interswitch-quickteller/client"
)

var (
	phoenixClientRegistration         = client.Endpoint{http.MethodPost, "api/v1/phoenix/client/clientRegistration"}
	phoenixCompleteClientRegistration = client.Endpoint{http.MethodPost, "api/v1/phoenix/client/completeClientRegistration"}
)

func (s *phoenix) ClientRegistration(ctx context.Context) (out ClientRegistrationResponse, er api.Error) {
	var err error
	var param ClientRegistrationRequest
	if err = param.FromContext(ctx, &param); err != nil {
		return out, api.RequestLoadError[ClientRegistrationRequest](err)
	} else if err = param.LoadPhoenixParams(ctx, s.client); err != nil {
		return out, api.ServiceError(err)
	}
	return client.RawRequest[ClientRegistrationRequest, ClientRegistrationResponse](
		s.client, getContextWithRequestID(ctx, uuid.MustParse(param.RequestReference)), param, phoenixClientRegistration)
}
