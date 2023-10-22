package api

import (
	"github.com/google/uuid"
	"github.com/kod2ulz/gostart/api"
	"github.com/kod2ulz/interswitch-quickteller/client"
)

type ClientRegistrationRequest struct {
	TerminalId             string `json:"terminalId"`
	AppVersion             string `json:"appVersion,omitempty"`
	SerialId               string `json:"serialId"`
	RequestReference       string `json:"requestReference"`
	GprsCoordinate         string `json:"gprsCoordinate,omitempty"`
	Name                   string `json:"name"`
	Nin                    string `json:"nin"`
	PhoneNumber            string `json:"phoneNumber"`
	Gender                 string `json:"gender,omitempty"`
	EmailAddress           string `json:"emailAddress,omitempty"`
	OwnerPhoneNumber       string `json:"ownerPhoneNumber"`
	PublicKey              string `json:"publicKey"`
	ClientSessionPublicKey string `json:"clientSessionPublicKey"`
	api.RequestModal[ClientRegistrationRequest]
}

func (r *ClientRegistrationRequest) LoadRequestDefaults() (err error) {
	if r.RequestReference == "" {
		r.RequestReference = uuid.New().String()
	}
	return
}

func (r *ClientRegistrationRequest) LoadPhoenixParams(phoenix *client.Phoenix) (err error) {
	if err = r.LoadRequestDefaults(); err != nil {
		return
	}
	conf := phoenix.Config()
	r.Nin = conf.NIN
	r.Name = conf.Name
	r.SerialId = conf.SerialID
	r.TerminalId = conf.TerminalID
	r.PhoneNumber = conf.PhoneNumber
	r.OwnerPhoneNumber = conf.PhoneNumber
	r.PublicKey = phoenix.Rsa().Public().Base64()
	r.ClientSessionPublicKey = phoenix.Ecdh().Public().Base64()
	return
}

type CompleteClientRegistrationRequest struct {
	TerminalId           string `json:"terminalId"`
	AppVersion           string `json:"appVersion,omitempty"`
	SerialId             string `json:"serialId"`
	RequestReference     string `json:"requestReference"`
	GprsCoordinate       string `json:"gprsCoordinate,omitempty"`
	Otp                  string `json:"otp,omitempty"`
	Password             string `json:"password"`
	TransactionReference string `json:"transactionReference"`
}
