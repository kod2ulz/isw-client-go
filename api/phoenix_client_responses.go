package api

type ClientRegistrationResponse struct {
	TransactionReference   string `json:"transactionReference,omitempty"`
	AuthToken              string `json:"authToken,omitempty"`
	ServerSessionPublicKey string `json:"serverSessionPublicKey,omitempty"`
}


type ClientResponse struct {
	Id                      int64  `json:"id,omitempty"`
	CreatedOn               string `json:"createdOn,omitempty"`
	CreatedBy               string `json:"createdBy,omitempty"`
	LastUpdatedOn           string `json:"lastUpdatedOn,omitempty"`
	LastUpdatedBy           string `json:"lastUpdatedBy,omitempty"`
	ClientId                string `json:"clientId,omitempty"`
	Secret                  string `json:"secret,omitempty"`
	TerminalId              string `json:"terminalId,omitempty"`
	AuthTokenExpireInterval int32  `json:"authTokenExpireInterval,omitempty"`
	OtpExpireDuration       int32  `json:"otpExpireDuration,omitempty"`
	SmsRoute                string `json:"smsRoute,omitempty"`
	AllowedIps              string `json:"allowedIps,omitempty"`
	DeniedIps               string `json:"deniedIps,omitempty"`
	ClientSecretClear       string `json:"clientSecretClear,omitempty"`
	Name                    string `json:"name,omitempty"`
	Rpm                     int32  `json:"rpm,omitempty"`
	Authorised              bool   `json:"authorised,omitempty"`
	CallBack                string `json:"callBack,omitempty"`
	EncTransactional        string `json:"encTransactional,omitempty"`
	CardPresent             bool   `json:"cardPresent,omitempty"`
	CurrencySymbol          string `json:"currencySymbol,omitempty"`
	CurrencyCode            string `json:"currencyCode,omitempty"`
	CountryCode             string `json:"countryCode,omitempty"`
	PasswordAgeDays         int32  `json:"passwordAgeDays,omitempty"`
	Iin                     string `json:"iin,omitempty"`
	Active                  bool   `json:"active,omitempty"`
	UsesOtpLogins           bool   `json:"usesOtpLogins,omitempty"`
	EnableIpValidation      bool   `json:"enableIpValidation,omitempty"`
	DeviceClient            bool   `json:"deviceClient,omitempty"`
	IIN                     string `json:"IIN,omitempty"`
	Transactional           bool   `json:"transactional,omitempty"`
	Class                   string `json:"@class"`
}