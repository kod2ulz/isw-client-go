package main

import (
	"github.com/kod2ulz/gostart/app"
	"github.com/kod2ulz/gostart/utils"
	"github.com/kod2ulz/gostart/storage"
	"github.com/kod2ulz/interswitch-quickteller/api"
	isw "github.com/kod2ulz/interswitch-quickteller/client"
	"github.com/kod2ulz/interswitch-quickteller/sql/db"
)

func main() {
	a := app.Init()
	ctx, log := a.Ctx(), a.Log()

	db, err := db.InitSQL(ctx, log, storage.Config("ISW_DB"))
	utils.Error.Fail(log.Entry, err, "failed to connect to database")
	defer utils.ErrorFunc[utils.ShFunc1](a, db.Conn.Close, "failed to close database connection")

	phoenixConf := isw.NewPhoenixClientConfig()
	phoenixClient, err := isw.PhoenixClient(ctx, log, isw.WithPhoenixConfig(phoenixConf), isw.WithPhoenixDB(db))
	utils.Error.Log(log.Entry, err, "failed to initialise phoenix client")
	
	phoenixAPI, err := api.Phoenix(ctx, log, api.WithPhoenixClient(phoenixClient))
	utils.Error.Log(log.Entry, err, "failed to initialise phoenix api")
	reg := api.ClientRegistrationRequest{
		AppVersion:       a.Config().Version,
	}
	res, err := phoenixAPI.ClientRegistration(reg.InContext(ctx, reg))
	utils.Error.Log(log.Entry, err, "client registration encountered error")
	log.WithField("res", res).Info()
}
