dir                    := $(shell pwd)
data_path              := $(dir)/sql
env_path               := $(dir)/.env
schema                 := interswitch
migration_sql_path     := $(data_path)/scripts
migration_create_path  := $(migration_sql_path)/$(schema)
migrations_path        := /tmp/interswitch/migrations/scripts
models_path            := ${data_path}/db/${schema}
queries_path           := ${data_path}/queries/${schema}
db_driver              := ${ISW_DB_DRIVER}
gostart_lib            := github.com/kod2ulz/gostart
gostart_dir            := /code/kod2ulz/gostart
db_connection_string   := "user=${ISW_DB_USERNAME} password=${ISW_DB_PASSWORD} host=${ISW_DB_HOST} port=${ISW_DB_PORT} dbname=${ISW_DB_DATABASE} sslmode=disable"

# migration
migration-status: validate-db-env pre-goose
	goose -dir $(migrations_path) $(db_driver) $(db_connection_string) status

migrate-up: validate-db-env pre-goose 
	goose -v -dir $(migrations_path) $(db_driver) $(db_connection_string) up

migrate-up-to: validate-db-env pre-goose
	goose -dir $(migrations_path) $(db_driver) $(db_connection_string) up-to ${until}

migrate-down: validate-db-env pre-goose
	goose -v -dir $(migrations_path) $(db_driver) $(db_connection_string) down

migrate-down-to: validate-db-env pre-goose
	goose -dir $(migrations_path) $(db_driver) $(db_connection_string) down-to ${until}

migrate-reset: validate-db-env pre-goose
	goose -dir $(migrations_path) $(db_driver) $(db_connection_string) reset

migrate-bounce: validate-db-env 
	make migrate-reset && make migrate-up

migration: validate-name sqlc-init
	goose -dir $(migration_create_path) create $(name) sql

pre-goose: 
	mkdir -p $(migrations_path) && rm -rf $(migrations_path)/*.sql && cp $(migration_sql_path)/*/*.sql $(migrations_path) 

# db-model management
sqlc-init:
	mkdir -p $(migration_create_path) ${models_path} ${queries_path}

sqlc:
	sqlc generate

env: validate-env-file
	export $(shell cat ${env_path} | tr -d ' ' | egrep -v '^#|^$$' | xargs -L 1)

update-gostart: validate-tag
	go get -u $(gostart_lib)@$(tag)

autoupgrade-gostart:
	make update-gostart tag=$(shell git -C $(gostart_dir) rev-parse --short HEAD) && go mod tidy && go test ./...

validate-tag:
ifndef tag
	$(error tag is undefined. syntax: make <command> tag=xxx. when unsure, set tag=latest)
endif

validate-name:
ifndef name
	$(error name is undefined. please specify migration name as name=<do_some_stuff>)
endif

validate-env-file:
	if [ ! -f $(env_path) ]; then echo 'env file missing at $(env_path)'; false; fi

validate-db-env:
ifndef ISW_DB_DRIVER
	$(error ISW_DB_DRIVER is undefined. please define ISW_DB_DRIVER=<DATABASE_DRIVER>)
endif
ifndef ISW_DB_USERNAME
	$(error ISW_DB_USERNAME is undefined. please define ISW_DB_USERNAME=<DATABASE_USER>)
endif
ifndef ISW_DB_PASSWORD
	$(error ISW_DB_PASSWORD is undefined. please define ISW_DB_PASSWORD=<DATABASE_PASSWORD>)
endif
ifndef ISW_DB_DATABASE
	$(error ISW_DB_DATABASE is undefined. please define ISW_DB_DATABASE=<DATABASE_NAME>)
endif
ifndef ISW_DB_HOST
	$(error ISW_DB_HOST is undefined. please define ISW_DB_HOST=<DATABASE_HOST>)
endif
ifndef ISW_DB_PORT
	$(error ISW_DB_PORT is undefined. please define ISW_DB_PORT=<DATABASE_PORT>)
endif



validate-package:
ifndef package
	$(error package is undefined. please specify a package as package=<package>)
endif

# project dev workflow
packages:
	go mod download
	
tidy:
	go mod tidy

run: validate-env-file
	$(shell cat ${dir}/.env | tr -d ' ' | xargs -L 1) go run main.go

test-gen: validate-package
	cd $(package) && ginkgo generate $(package)

test-init:
	ginkgo bootstrap

test:
	go test ./...