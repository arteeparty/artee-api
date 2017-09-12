NOW := $(shell date +"%s")
DATABASE_URL := "postgresql://artee:ArteeParty2017@localhost:5432/artee?sslmode=disable"

.PHONY: build

clean:
	rm -rf build/*

run: build
	./build/artee

build: *.go
	go build -o build/artee .

build-linux: *.go
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o build/artee-api-linux64 .

deploy: build-linux
	scp build/artee-api-linux64 api.artee.party:~
	ssh  api.artee.party "sh deploy.sh"

new-migration:
	touch migrations/${NOW}_$(TITLE).up.sql
	touch migrations/${NOW}_$(TITLE).down.sql

migrate:
	migrate -path ./migrations -database $(DATABASE_URL) up
