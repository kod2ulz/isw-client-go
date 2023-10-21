package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/jackc/pgx/v4/log/logrusadapter"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/kod2ulz/gostart/logr"
	"github.com/kod2ulz/gostart/storage"
	isw "github.com/kod2ulz/interswitch-quickteller/sql/db/interswitch"
)

type IswQueries struct{ *isw.Queries }
type SqlDB struct {
	*Queries
	*IswQueries
	Conn *pgxpool.Pool
	conf *pgxpool.Config
}

func InitSQL(ctx context.Context, log *logr.Logger, conf *storage.Conf) (out *SqlDB, err error) {
	out = &SqlDB{}
	if out.conf, err = pgxpool.ParseConfig(conf.ConnectionString()); err != nil {
		return
	}
	out.conf.ConnConfig.Logger = logrusadapter.NewLogger(log)
	if out.Conn, err = pgxpool.ConnectConfig(ctx, out.conf); err != nil {
		return nil, err
	}
	out.Queries = New(out.Conn)
	out.IswQueries = &IswQueries{Queries: isw.New(out.Conn)}
	return
}

func IsSqlNoRows(err error) bool {
	return err != nil && (errors.Is(err, sql.ErrNoRows) || strings.HasSuffix(err.Error(), "no rows in result set"))
}
