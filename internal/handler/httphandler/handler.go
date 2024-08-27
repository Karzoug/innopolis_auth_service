package httphandler

import (
	"authservice/internal/domain"
	"authservice/internal/service"
	"errors"
	"net/http"

	"go.mongodb.org/mongo-driver/bson/primitive"

	_ "authservice/api"

	httpSwagger "github.com/swaggo/http-swagger/v2"
)

//	@title			Swagger auth API
//	@version		1.0
//	@description	Authorization service.
//	@termsOfService	http://swagger.io/terms/

//	@host	localhost:8000
func NewRouter() *http.ServeMux {
	router := http.NewServeMux()
	router.Handle("/sign_up", CORS(LogUser(http.HandlerFunc(SignUp))))
	router.Handle("/sign_in", CORS(LogUser(http.HandlerFunc(SignIn))))

	router.Handle("/get_user_info", CORS(Auth(LogUser(http.HandlerFunc(GetUserInfo)))))
	router.Handle("/set_user_info", CORS(Auth(LogUser(http.HandlerFunc(SetUserInfo)))))
	router.Handle("/change_psw", CORS(Auth(LogUser(http.HandlerFunc(ChangePsw)))))
	// admin handlers
	router.Handle("/admin/get_user_info", CORS(Auth(isAdmin(LogUser(http.HandlerFunc(AdminGetUserInfo))))))

	router.Handle("/v2/get_user_info", CORS(Auth(LogUser(http.HandlerFunc(GetUserInfoV2)))))

	router.Handle("GET /api/*", httpSwagger.Handler(
		httpSwagger.URL("http://localhost:8000/api/doc.json"), //The url pointing to API definition
	))

	return router
}

// GetUserInfoV2 gets user info.
//
//	@Summary		Get user info
//	@Description	Get user info: short for user, full for admin
//	@Tags			account
//	@Accept			json
//	@Produce		json
//	@Param			User-ID	header		string	true	"user token"
//	@Failure		default	{object}	HTTPResponse{data=nil}
//	@Success		200		{object}	HTTPResponse{data=domain.UserInfo}	"short info for user"
//	@Success		200		{object}	HTTPResponse{data=domain.User}		"full info for admin"
//	@Router			/v2/get_user_info [get]
func GetUserInfoV2(resp http.ResponseWriter, req *http.Request) {
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

	authorUserID, _ := primitive.ObjectIDFromHex(req.Header.Get(HeaderUserID))
	authorFullInfo, err := service.GetUserFullInfo(authorUserID)
	if err != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		respBody.SetError(err)
		return
	}

	switch authorFullInfo.Role {
	case domain.UserRoleAdmin:
		info, err := service.GetUserFullInfo(userID)
		if err != nil {
			resp.WriteHeader(http.StatusNotFound)
			respBody.SetError(err)
			return
		}
		respBody.SetData(info)
		return
	case domain.UserRoleDefault:
		if authorUserID != userID {
			resp.WriteHeader(http.StatusForbidden)
			respBody.SetError(errors.New("user is not admin to get info about someone else"))
			return
		}
		info, err := service.GetUserShortInfo(userID)
		if err != nil {
			resp.WriteHeader(http.StatusNotFound)
			respBody.SetError(err)
		}

		respBody.SetData(info)
	}
}
