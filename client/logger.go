package client

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgtype"
	"github.com/kod2ulz/gostart/api"
	"github.com/kod2ulz/gostart/collections"
	"github.com/kod2ulz/gostart/logr"
	dbi "github.com/kod2ulz/interswitch-quickteller/sql/db/interswitch"
)

type phoenixLogger struct {
	*logr.Logger
	px *Phoenix
}

func (l phoenixLogger) getRequestID(ctx context.Context) (out uuid.UUID) {
	var ok bool
	var err error
	if val := ctx.Value(api.RequestID); val != nil {
		if out, ok = val.(uuid.UUID); ok {
			return
		} else if out, err = uuid.Parse(fmt.Sprint(val)); err == nil {
			return
		}
	}
	return uuid.New()
}

func (l phoenixLogger) Request(ctx context.Context, requestID uuid.UUID, method, url string, body any, headers map[string][]string) (call dbi.InterswitchApiCall, err error) {
	var request pgtype.JSONB
	data := l.jsonBody(body, headers, nil)
	request.Set(data)
	if call, err = l.px.db.LogApiRequest(ctx, dbi.LogApiRequestParams{
		RequestID: requestID,
		RemoteIp:  l.px.hostIP,
		Method:    method,
		Url:       url,
		Request:   request,
	}); err != nil {
		l.WithError(err).WithField("data", data).Error("failed to save api request")
	} else {
		l.WithField("requestId", call.RequestID).Debug()
	}
	return
}

func (l phoenixLogger) Response(ctx context.Context, requestId uuid.UUID, code int, body any, headers map[string][]string, cookies []*http.Cookie) (call dbi.InterswitchApiCall, err error) {
	var response pgtype.JSONB
	data := l.jsonBody(body, headers, cookies)
	response.Set(data)
	if call, err = l.px.db.LogApiResponse(ctx, dbi.LogApiResponseParams{
		Response:     l.jsonBody(body, headers, cookies),
		ResponseCode: int32(code),
		RequestID:    requestId,
	}); err == nil {
		l.WithField("requestId", call.RequestID).Debug()
	} else {
		l.WithError(err).WithField("data", data).Error("failed to save api request")
	}
	return
}

func (l phoenixLogger) payloadData(body any, headers map[string][]string, cookies []*http.Cookie) (data collections.Map[string, any]) {
	data = make(collections.Map[string, any])
	if body != nil {
		data["body"] = body
	}
	if headers != nil && len(headers) > 0 {
		data["headers"] = headers
	}
	if cookies != nil && len(cookies) > 0 {
		data["cookies"] = cookies
	}
	return
}

func (l phoenixLogger) jsonBody(body any, headers map[string][]string, cookies []*http.Cookie) pgtype.JSONB {
	var outJson pgtype.JSONB
	outJson.Set(l.payloadData(body, headers, cookies))
	return outJson
}
