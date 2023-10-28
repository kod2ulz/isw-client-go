package client

import "github.com/kod2ulz/gostart/utils"

type PhoenixConfig struct {
	Host            string
	TerminalID      string
	ClientID        string
	ClientSecret    string
	Timezone        string
	Name            string
	PhoneNumber     string
	Email           string
	NIN             string
	SerialID        string
	RsaBitSize      int
	StorageBucket   string
	StorageFolder   string
	StorageRsaPath  string
	StorageEcdhPath string
}

func NewPhoenixClientConfig(prefix ...string) *PhoenixConfig {
	env := utils.Env.Helper(prefix...).OrDefault("PHOENIX_CLIENT")
	return &PhoenixConfig{
		Host:            env.MustGet("HOST").String(),
		ClientID:        env.MustGet("ID").String(),
		TerminalID:      env.MustGet("TERMINAL_ID").String(),
		ClientSecret:    env.MustGet("SECRET").String(),
		Timezone:        env.Get("TIMEZONE", "Africa/Kampala").String(),
		Email:           env.Get("EMAIL", "ugandan@mail.ug").String(),
		Name:            env.Get("NAME", "NDI MUNAUGANDA").String(),
		NIN:             env.Get("NIN", "CM8101234568NH").String(),
		PhoneNumber:     env.Get("PHONE", "0701234567").String(),
		RsaBitSize:      env.Get("RSA_BIT_SIZE", "2048").Int(),
		SerialID:        env.Get("SERIAL_ID", "client.phoenix.v1").String(),
		StorageBucket:   env.Get("STORAGE_BUCKET", "phoenix").String(),
		StorageFolder:   env.Get("STORAGE_FOLDER", "phoenix").String(),
		StorageRsaPath:  env.Get("STORAGE_RSA_PATH", "rsa.key").String(),
		StorageEcdhPath: env.Get("STORAGE_ECDH_PATH", "ecdh.key").String(),
	}
}
