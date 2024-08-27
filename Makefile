gen-swagger:
	swag fmt -d ./internal/handler/httphandler
	swag init -g ./internal/handler/httphandler/handler.go -o ./api/