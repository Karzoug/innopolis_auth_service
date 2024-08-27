package httphandler

import (
	"authservice/internal/service"
	"errors"
	"net/http"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// AdminGetUserInfo gets full user info.
//
//	@Summary		Get full user info
//	@Description	Get full user info, only for admins
//	@Tags			account
//	@Accept			json
//	@Produce		json
//	@Param			User-ID	header		string	true	"admin token"
//	@Param			user_id	query		string	true	"user ID"
//	@Failure		default	{object}	HTTPResponse{data=nil}
//	@Success		200		{object}	HTTPResponse{data=domain.User}
//	@Router			/admin/get_user_info [get]
func AdminGetUserInfo(resp http.ResponseWriter, req *http.Request) {
	respBody := &HTTPResponse{}
	defer func() {
		resp.Write(respBody.Marshall())
	}()

	id := req.URL.Query().Get("user_id")
	userID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("invalid input"))
		return
	}

	info, err := service.GetUserFullInfo(userID)
	if err != nil {
		resp.WriteHeader(http.StatusNotFound)
		respBody.SetError(err)
	}

	respBody.SetData(info)
}
