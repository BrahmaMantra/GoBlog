package controllers

import (
	"encoding/json"
	"fmt"
	"goBlog/helpers"
	"goBlog/models"
	"goBlog/system"
	"io"
	"net/http"

	oauth "github.com/alimoeeny/gooauth2"
	"github.com/cihub/seelog"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

// GithubUserInfo 定义 GitHub 用户信息的结构体
type GithubUserInfo struct {
	AvatarURL         string      `json:"avatar_url"`          // 用户头像 URL
	Bio               interface{} `json:"bio"`                 // 用户简介
	Blog              string      `json:"blog"`                // 用户博客地址
	Company           interface{} `json:"company"`             // 用户公司信息
	CreatedAt         string      `json:"created_at"`          // 用户创建时间
	Email             interface{} `json:"email"`               // 用户邮箱
	EventsURL         string      `json:"events_url"`          // 用户事件 URL
	Followers         int         `json:"followers"`           // 粉丝数量
	FollowersURL      string      `json:"followers_url"`       // 粉丝列表 URL
	Following         int         `json:"following"`           // 关注数量
	FollowingURL      string      `json:"following_url"`       // 关注列表 URL
	GistsURL          string      `json:"gists_url"`           // Gists URL
	GravatarID        string      `json:"gravatar_id"`         // Gravatar ID
	Hireable          interface{} `json:"hireable"`            // 是否可雇佣
	HTMLURL           string      `json:"html_url"`            // GitHub 主页 URL
	ID                int         `json:"id"`                  // 用户 ID
	Location          interface{} `json:"location"`            // 用户位置
	Login             string      `json:"login"`               // 用户登录名
	Name              interface{} `json:"name"`                // 用户姓名
	OrganizationsURL  string      `json:"organizations_url"`   // 组织 URL
	PublicGists       int         `json:"public_gists"`        // 公开 Gists 数量
	PublicRepos       int         `json:"public_repos"`        // 公开仓库数量
	ReceivedEventsURL string      `json:"received_events_url"` // 收到的事件 URL
	ReposURL          string      `json:"repos_url"`           // 仓库 URL
	SiteAdmin         bool        `json:"site_admin"`          // 是否是管理员
	StarredURL        string      `json:"starred_url"`         // 星标仓库 URL
	SubscriptionsURL  string      `json:"subscriptions_url"`   // 订阅 URL
	Type              string      `json:"type"`                // 用户类型
	UpdatedAt         string      `json:"updated_at"`          // 最后更新时间
	URL               string      `json:"url"`                 // 用户 URL
}

// SigninGet 处理登录页面的 GET 请求
func SigninGet(c *gin.Context) {
	c.HTML(http.StatusOK, "auth/signin.html", gin.H{
		"cfg": system.GetConfiguration(), // 将配置信息传递给模板
	})
}

// SignupGet 处理注册页面的 GET 请求
func SignupGet(c *gin.Context) {
	c.HTML(http.StatusOK, "auth/signup.html", gin.H{
		"cfg": system.GetConfiguration(), // 将配置信息传递给模板
	})
}

// LogoutGet 处理用户登出的 GET 请求
func LogoutGet(c *gin.Context) {
	s := sessions.Default(c)
	s.Clear() // 清除会话数据
	s.Save()
	c.Redirect(http.StatusSeeOther, "/signin") // 重定向到登录页面
}

// SignupPost 处理用户注册的 POST 请求
func SignupPost(c *gin.Context) {
	var (
		err error
	)
	email := c.PostForm("email")         // 获取邮箱
	telephone := c.PostForm("telephone") // 获取电话
	password := c.PostForm("password")   // 获取密码

	// 检查邮箱和密码是否为空
	if len(email) == 0 || len(password) == 0 {
		c.HTML(http.StatusOK, "auth/signup.html", gin.H{
			"message": "email or password cannot be null", // 返回错误信息
			"cfg":     system.GetConfiguration(),
		})
		return
	}

	// 创建用户对象
	user := &models.User{
		Email:     email,
		Telephone: telephone,
		Password:  password,
		IsAdmin:   true,
	}
	user.Password = helpers.Md5(user.Email + user.Password) // 对密码进行 MD5 加密

	// 插入用户到数据库
	err = user.Insert()
	if err != nil {
		c.HTML(http.StatusOK, "auth/signup.html", gin.H{
			"message": "email already exists", // 返回错误信息
			"cfg":     system.GetConfiguration(),
		})
		return
	}
	c.Redirect(http.StatusMovedPermanently, "/signin") // 注册成功后重定向到登录页面
}

// SigninPost 处理用户登录的 POST 请求
func SigninPost(c *gin.Context) {
	var (
		err  error
		user *models.User
	)
	username := c.PostForm("username") // 获取用户名
	password := c.PostForm("password") // 获取密码

	// 检查用户名和密码是否为空
	if username == "" || password == "" {
		c.HTML(http.StatusOK, "auth/signin.html", gin.H{
			"message": "username or password cannot be null", // 返回错误信息
			"cfg":     system.GetConfiguration(),
		})
		return
	}

	// 根据用户名获取用户
	user, err = models.GetUserByUsername(username)
	if err != nil || user.Password != helpers.Md5(username+password) {
		c.HTML(http.StatusOK, "auth/signin.html", gin.H{
			"message": "invalid username or password", // 返回错误信息
			"cfg":     system.GetConfiguration(),
		})
		return
	}

	// 检查用户是否被锁定
	if user.LockState {
		c.HTML(http.StatusOK, "auth/signin.html", gin.H{
			"message": "Your account have been locked", // 返回错误信息
			"cfg":     system.GetConfiguration(),
		})
		return
	}

	// 设置 sessions
	s := sessions.Default(c)
	s.Clear()
	s.Set(SessionKey, user.ID) // 将用户 ID 存入sessions
	s.Save()

	// 根据用户角色重定向到不同页面
	if user.IsAdmin {
		c.Redirect(http.StatusMovedPermanently, "/admin/index") // 管理员重定向到管理页面
	} else {
		c.Redirect(http.StatusMovedPermanently, "/") // 普通用户重定向到首页
	}
}

// Oauth2Callback 处理 GitHub OAuth2 回调
func Oauth2Callback(c *gin.Context) {
	var (
		userInfo *GithubUserInfo
		user     *models.User
	)
	code := c.Query("code")   // 获取授权码
	state := c.Query("state") // 获取状态码

	// 验证状态码
	session := sessions.Default(c)
	if len(state) == 0 || state != session.Get(SessionGithubState) {
		c.Abort() // 状态码不匹配，终止请求
		return
	}
	// 从会话中删除状态码
	session.Delete(SessionGithubState)
	session.Save()

	// 通过授权码获取访问令牌
	token, err := exchangeTokenByCode(code)
	if err != nil {
		seelog.Errorf("exchangeTokenByCode err: %v", err)
		c.Redirect(http.StatusMovedPermanently, "/signin") // 重定向到登录页面
		return
	}

	// 通过访问令牌获取 GitHub 用户信息
	userInfo, err = getGithubUserInfoByAccessToken(token)
	if err != nil {
		seelog.Errorf("getGithubUserInfoByAccessToken err: %v", err)
		c.Redirect(http.StatusMovedPermanently, "/signin") // 重定向到登录页面
		return
	}

	// 检查用户是否已登录
	sessionUser, exists := c.Get(ContextUserKey)
	if exists { // 已登录
		user = sessionUser.(*models.User)
		if _, e := models.IsGithubIdExists(userInfo.Login, user.ID); e != nil { // 未绑定 GitHub
			if user.IsAdmin {
				user.GithubLoginId = userInfo.Login
			}
			user.AvatarUrl = userInfo.AvatarURL
			user.GithubUrl = userInfo.HTMLURL
			err = user.UpdateGithubUserInfo() // 更新 GitHub 用户信息
		} else {
			err = errors.New("this github loginId has bound another account.") // GitHub 已绑定其他账号
		}
	} else { // 未登录
		user = &models.User{
			GithubLoginId: userInfo.Login,
			AvatarUrl:     userInfo.AvatarURL,
			GithubUrl:     userInfo.HTMLURL,
		}
		user, err = user.FirstOrCreate() // 创建或获取用户
		if err == nil {
			if user.LockState {
				err = errors.New("Your account have been locked.") // 账号被锁定
				HandleMessage(c, err.Error())
				return
			}
		}
	}

	if err == nil {
		s := sessions.Default(c)
		s.Clear()
		s.Set(SessionKey, user.ID) // 将用户 ID 存入会话
		s.Save()
		if user.IsAdmin {
			c.Redirect(http.StatusMovedPermanently, "/admin/index") // 管理员重定向到管理页面
		} else {
			c.Redirect(http.StatusMovedPermanently, "/") // 普通用户重定向到首页
		}
		return
	}
}

// exchangeTokenByCode 通过授权码交换访问令牌
func exchangeTokenByCode(code string) (accessToken string, err error) {
	var (
		transport *oauth.Transport
		token     *oauth.Token
		cfg       = system.GetConfiguration()
	)
	transport = &oauth.Transport{Config: &oauth.Config{
		ClientId:     cfg.Github.ClientId,     // GitHub 客户端 ID
		ClientSecret: cfg.Github.ClientSecret, // GitHub 客户端密钥
		RedirectURL:  cfg.Github.RedirectURL,  // 回调 URL
		TokenURL:     cfg.Github.TokenUrl,     // 令牌 URL
		Scope:        cfg.Github.Scope,        // 授权范围
	}}
	token, err = transport.Exchange(code) // 交换访问令牌
	if err != nil {
		return
	}
	accessToken = token.AccessToken
	// 缓存令牌
	tokenCache := oauth.CacheFile("./request.token")
	if err := tokenCache.PutToken(token); err != nil {
		seelog.Errorf("tokenCache.PutToken err: %v", err)
	}
	return
}

// getGithubUserInfoByAccessToken 通过访问令牌获取 GitHub 用户信息
func getGithubUserInfoByAccessToken(token string) (*GithubUserInfo, error) {
	// 创建请求
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	// 发送请求
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// 检查速率限制
	limit := resp.Header.Get("X-RateLimit-Limit")
	remaining := resp.Header.Get("X-RateLimit-Remaining")
	fmt.Printf("Rate limit: %s/%s\n", remaining, limit)

	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %v", err)
		}

		var apiError struct {
			Message          string `json:"message"`
			DocumentationURL string `json:"documentation_url"`
		}
		if err := json.Unmarshal(body, &apiError); err != nil {
			return nil, fmt.Errorf("failed to parse error response: %v", err)
		}

		return nil, fmt.Errorf("GitHub API error: %s (Documentation: %s)", apiError.Message, apiError.DocumentationURL)
	}

	// 解析响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var userInfo GithubUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %v", err)
	}

	return &userInfo, nil
}

// ProfileGet 处理用户个人资料页面的 GET 请求
func ProfileGet(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/profile.html", gin.H{
		"user":     c.MustGet(ContextUserKey),      // 获取当前用户
		"comments": models.MustListUnreadComment(), // 获取未读评论
		"cfg":      system.GetConfiguration(),      // 传递配置信息
	})
}

// ProfileUpdate 处理用户个人资料更新的 POST 请求
func ProfileUpdate(c *gin.Context) {
	var (
		err error
		res = gin.H{}
	)
	defer writeJSON(c, res)
	avatarUrl := c.PostForm("avatarUrl") // 获取头像 URL
	nickName := c.PostForm("nickName")   // 获取昵称
	sessionUser, _ := c.Get(ContextUserKey)
	user := sessionUser.(*models.User)
	err = user.UpdateProfile(avatarUrl, nickName) // 更新个人资料
	if err != nil {
		res["message"] = err.Error()
		return
	}
	res["succeed"] = true
	res["user"] = models.User{AvatarUrl: avatarUrl, NickName: nickName}
}

// BindEmail 处理绑定邮箱的 POST 请求
func BindEmail(c *gin.Context) {
	var (
		err error
		res = gin.H{}
	)
	defer writeJSON(c, res)
	email := c.PostForm("email") // 获取邮箱
	sessionUser, _ := c.Get(ContextUserKey)
	user := sessionUser.(*models.User)
	if len(user.Email) > 0 {
		res["message"] = "email have bound" // 邮箱已绑定
		return
	}
	_, err = models.GetUserByUsername(email)
	if err == nil {
		res["message"] = "email have be registered" // 邮箱已被注册
		return
	}
	err = user.UpdateEmail(email) // 更新邮箱
	if err != nil {
		res["message"] = err.Error()
		return
	}
	res["succeed"] = true
}

// UnbindEmail 处理解绑邮箱的 POST 请求
func UnbindEmail(c *gin.Context) {
	var (
		err error
		res = gin.H{}
	)
	defer writeJSON(c, res)
	sessionUser, _ := c.Get(ContextUserKey)
	user := sessionUser.(*models.User)
	if user.Email == "" {
		res["message"] = "email haven't bound" // 邮箱未绑定
		return
	}
	err = user.UpdateEmail("") // 解绑邮箱
	if err != nil {
		res["message"] = err.Error()
		return
	}
	res["succeed"] = true
}

// UnbindGithub 处理解绑 GitHub 的 POST 请求
func UnbindGithub(c *gin.Context) {
	var (
		err error
		res = gin.H{}
	)
	defer writeJSON(c, res)
	sessionUser, _ := c.Get(ContextUserKey)
	user := sessionUser.(*models.User)
	if user.GithubLoginId == "" {
		res["message"] = "github haven't bound" // GitHub 未绑定
		return
	}
	user.GithubLoginId = ""
	err = user.UpdateGithubUserInfo() // 解绑 GitHub
	if err != nil {
		res["message"] = err.Error()
		return
	}
	res["succeed"] = true
}

// UserIndex 处理用户管理页面的 GET 请求
func UserIndex(c *gin.Context) {
	users, _ := models.ListUsers() // 获取用户列表
	c.HTML(http.StatusOK, "admin/user.html", gin.H{
		"users":    users,
		"user":     c.MustGet(ContextUserKey),      // 获取当前用户
		"comments": models.MustListUnreadComment(), // 获取未读评论
		"cfg":      system.GetConfiguration(),      // 传递配置信息
	})
}

// UserLock 处理锁定/解锁用户的 POST 请求
func UserLock(c *gin.Context) {
	var (
		err  error
		id   uint
		res  = gin.H{}
		user *models.User
	)
	defer writeJSON(c, res)
	id, err = ParamUint(c, "id") // 获取用户 ID
	if err != nil {
		res["message"] = err.Error()
		return
	}
	user, err = models.GetUser(id) // 获取用户
	if err != nil {
		res["message"] = err.Error()
		return
	}
	user.LockState = !user.LockState // 切换锁定状态
	err = user.Lock()                // 更新用户锁定状态
	if err != nil {
		res["message"] = err.Error()
		return
	}
	res["succeed"] = true
}
