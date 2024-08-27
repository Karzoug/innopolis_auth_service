package httphandler

import (
	"authservice/internal/domain"
	"authservice/internal/service"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// SignUp signs up new account.
//
//	@Summary		Sign up account
//	@Description	Sign up account with login and password
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			credentials	body		domain.LoginPassword	true	"login and password"
//	@Failure		default		{object}	HTTPResponse{data=nil}
//	@Success		200			{object}	HTTPResponse{data=string}
//	@Router			/sign_up [post]
func SignUp(resp http.ResponseWriter, req *http.Request) {
	respBody := &HTTPResponse{}
	defer func() {
		resp.Write(respBody.Marshall())
	}()

	var input domain.LoginPassword
	if err := readBody(req, &input); err != nil {
		resp.WriteHeader(http.StatusUnprocessableEntity)
		respBody.SetError(err)
		return
	}

	if !input.IsValid() {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("invalid input"))
		return
	}

	userToken, err := service.SignUp(&input)
	if err != nil {
		resp.WriteHeader(http.StatusConflict)
		respBody.SetError(err)
		return
	}

	respBody.SetData(userToken)
}

// SignIn signs in account.
//
//	@Summary		Sign in account
//	@Description	Sign in account with login and password
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			credentials	body		domain.LoginPassword	true	"login and password"
//	@Failure		default		{object}	HTTPResponse{data=nil}
//	@Success		200			{object}	HTTPResponse{data=string}
//	@Router			/sign_in [post]
func SignIn(resp http.ResponseWriter, req *http.Request) {

	respBody := &HTTPResponse{}
	defer func() {
		resp.Write(respBody.Marshall())
	}()

	var input domain.LoginPassword
	if err := readBody(req, &input); err != nil {
		resp.WriteHeader(http.StatusUnprocessableEntity)
		respBody.SetError(err)
		return
	}

	if !input.IsValid() {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("invalid input"))
		return
	}

	userToken, err := service.SignIn(&input)
	if err != nil {
		resp.WriteHeader(http.StatusNotFound)
		respBody.SetError(err)
		return
	}

	respBody.SetData(userToken)
}

// GetUserInfo gets user info.
//
//	@Summary		Get user info
//	@Description	Get short user info, only for users
//	@Tags			account
//	@Accept			json
//	@Produce		json
//	@Param			User-ID	header		string	true	"user token"
//	@Failure		default	{object}	HTTPResponse{data=nil}
//	@Success		200		{object}	HTTPResponse{data=domain.UserInfo}
//	@Router			/get_user_info [get]
func GetUserInfo(resp http.ResponseWriter, req *http.Request) {
	respBody := &HTTPResponse{}
	defer func() {
		resp.Write(respBody.Marshall())
	}()

	userID, _ := primitive.ObjectIDFromHex(req.Header.Get(HeaderUserID))

	info, err := service.GetUserShortInfo(userID)
	if err != nil {
		resp.WriteHeader(http.StatusNotFound)
		respBody.SetError(err)
	}

	respBody.SetData(info)
}

// SetUserInfo sets user info.
//
//	@Summary		Set user info
//	@Description	Set short user info, only for users
//	@Tags			account
//	@Accept			json
//	@Produce		json
//	@Param			user_info	body		SetUserInfoReq	true	"user info"
//	@Param			User-ID		header		string			true	"user token"
//	@Response		default		{object}	HTTPResponse{data=nil}
//	@Router			/set_user_info [post]
func SetUserInfo(resp http.ResponseWriter, req *http.Request) {
	respBody := &HTTPResponse{}
	defer func() {
		resp.Write(respBody.Marshall())
	}()

	var input SetUserInfoReq

	if err := readBody(req, &input); err != nil {
		resp.WriteHeader(http.StatusUnprocessableEntity)
		respBody.SetError(err)
		return
	}

	if !input.IsValid() {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("invalid input"))
		return
	}

	userID, _ := primitive.ObjectIDFromHex(req.Header.Get(HeaderUserID))

	if err := service.SetUserInfo(&domain.UserInfo{
		ID:   userID,
		Name: input.Name,
	}); err != nil {
		resp.WriteHeader(http.StatusNotFound)
		respBody.SetError(err)
		return
	}
}

// ChangePsw changes user password.
//
//	@Summary		Change user password
//	@Description	Change user password
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			password	body		ChangePswReq	true	"a new password"
//	@Param			User-ID		header		string			true	"user token"
//	@Response		default		{object}	HTTPResponse{data=nil}
//	@Router			/change_psw [post]
func ChangePsw(resp http.ResponseWriter, req *http.Request) {

	respBody := &HTTPResponse{}
	defer func() {
		resp.Write(respBody.Marshall())
	}()

	var input ChangePswReq

	if err := readBody(req, &input); err != nil {
		resp.WriteHeader(http.StatusUnprocessableEntity)
		respBody.SetError(err)
		return
	}

	if !input.IsValid() {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("invalid input"))
		return
	}

	userID, _ := primitive.ObjectIDFromHex(req.Header.Get(HeaderUserID))
	err := service.ChangePsw(&domain.UserPassword{
		ID:       userID,
		Password: input.Password,
	})
	if err != nil {
		resp.WriteHeader(http.StatusNotFound)
		respBody.SetError(err)
		return
	}
}

func readBody(req *http.Request, s any) error {

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}

	return json.Unmarshal(body, s)
}
