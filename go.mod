module github.com/pyzanode/controller

go 1.24.0

require (
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/websocket v1.5.1
	github.com/pyzanode/shared v0.0.0
)

require golang.org/x/crypto v0.48.0 // indirect

replace github.com/pyzanode/shared => ../shared
