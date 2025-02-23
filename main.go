package main

import (
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"

	"goBlog/controllers"
	"goBlog/helpers"
	"goBlog/models"
	"goBlog/system"

	"github.com/cihub/seelog"
	"github.com/claudiu/gocron"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func main() {

	// 解析命令行参数
	configFilePath := flag.String("C", "conf/conf.toml", "配置文件路径")
	logConfigPath := flag.String("L", "conf/seelog.xml", "日志配置文件路径")
	generate := flag.Bool("g", false, "生成示例配置文件")
	flag.Parse()

	// 如果指定了生成示例配置文件，则生成并退出
	if *generate {
		system.Generate()
		os.Exit(0)
	}

	// 初始化日志配置
	logger, err := seelog.LoggerFromConfigAsFile(*logConfigPath)
	if err != nil {
		seelog.Critical("解析seelog配置文件错误", err)
		return
	}
	seelog.ReplaceLogger(logger)
	defer seelog.Flush()

	// 加载系统配置文件
	if err := system.LoadConfiguration(*configFilePath); err != nil {
		seelog.Critical("解析配置文件错误", err)
		return
	}

	// 初始化数据库
	db, err := models.InitDB()
	if err != nil {
		seelog.Critical("打开数据库错误", err)
		return
	}
	defer func() {
		dbInstance, _ := db.DB()
		_ = dbInstance.Close()
	}()

	// 设置Gin运行模式为ReleaseMode
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// 设置模板、会话和共享数据中间件
	setTemplate(router)
	setSessions(router)
	router.Use(SharedData())

	// 定时任务
	gocron.Every(1).Day().Do(controllers.CreateXMLSitemap) // 每天生成XML站点地图
	gocron.Every(7).Days().Do(controllers.Backup)          // 每7天备份一次
	gocron.Start()

	// 设置静态文件目录
	router.Static("/static", filepath.Join(helpers.GetCurrentDirectory(), system.GetConfiguration().PublicDir))

	// 404处理
	router.NoRoute(controllers.Handle404)

	// 首页路由
	router.GET("/", controllers.IndexGet)
	router.GET("/index", controllers.IndexGet)

	// RSS订阅路由
	router.GET("/rss", controllers.RssGet)

	// 如果启用注册功能，设置注册路由
	// log.Printf("SignupEnabled: %v", system.GetConfiguration().SignupEnabled)
	if system.GetConfiguration().SignupEnabled {
		router.GET("/signup", controllers.SignupGet)
		router.POST("/signup", controllers.SignupPost)
	}

	// 用户登录和登出路由
	router.GET("/signin", controllers.SigninGet)
	router.POST("/signin", controllers.SigninPost)
	router.GET("/logout", controllers.LogoutGet)
	router.GET("/oauth2callback", controllers.Oauth2Callback)
	router.GET("/auth/:authType", controllers.AuthGet)

	// 验证码路由
	router.GET("/captcha", controllers.CaptchaGet)

	// 访客路由组，要求认证但不要求管理员权限
	visitor := router.Group("/visitor")
	visitor.Use(AuthRequired(false))
	{
		visitor.POST("/new_comment", controllers.CommentPost)
		visitor.POST("/comment/:id/delete", controllers.CommentDelete)
	}

	// 订阅者路由
	router.GET("/subscribe", controllers.SubscribeGet)
	router.POST("/subscribe", controllers.Subscribe)
	router.GET("/active", controllers.ActiveSubscriber)
	router.GET("/unsubscribe", controllers.UnSubscribe)

	// 页面、文章、标签、归档路由
	router.GET("/page/:id", controllers.PageGet)
	router.GET("/post/:id", controllers.PostGet)
	router.GET("/tag/:tag", controllers.TagGet)
	router.GET("/archives/:year/:month", controllers.ArchiveGet)

	// 链接路由
	router.GET("/link/:id", controllers.LinkGet)

	// 管理员路由组，要求认证且要求管理员权限
	authorized := router.Group("/admin")
	authorized.Use(AuthRequired(true))
	{
		// 管理员首页
		authorized.GET("/index", controllers.AdminIndex)

		// 图片上传
		authorized.POST("/upload", controllers.Upload)

		// 页面管理
		authorized.GET("/page", controllers.PageIndex)
		authorized.GET("/new_page", controllers.PageNew)
		authorized.POST("/new_page", controllers.PageCreate)
		authorized.GET("/page/:id/edit", controllers.PageEdit)
		authorized.POST("/page/:id/edit", controllers.PageUpdate)
		authorized.POST("/page/:id/publish", controllers.PagePublish)
		authorized.POST("/page/:id/delete", controllers.PageDelete)

		// 文章管理
		authorized.GET("/post", controllers.PostIndex)
		authorized.GET("/new_post", controllers.PostNew)
		authorized.POST("/new_post", controllers.PostCreate)
		authorized.GET("/post/:id/edit", controllers.PostEdit)
		authorized.POST("/post/:id/edit", controllers.PostUpdate)
		authorized.POST("/post/:id/publish", controllers.PostPublish)
		authorized.POST("/post/:id/delete", controllers.PostDelete)

		// 标签管理
		authorized.POST("/new_tag", controllers.TagCreate)

		// 用户管理
		authorized.GET("/user", controllers.UserIndex)
		authorized.POST("/user/:id/lock", controllers.UserLock)

		// 个人资料管理
		authorized.GET("/profile", controllers.ProfileGet)
		authorized.POST("/profile", controllers.ProfileUpdate)
		authorized.POST("/profile/email/bind", controllers.BindEmail)
		authorized.POST("/profile/email/unbind", controllers.UnbindEmail)
		authorized.POST("/profile/github/unbind", controllers.UnbindGithub)

		// 订阅者管理
		authorized.GET("/subscriber", controllers.SubscriberIndex)
		authorized.POST("/subscriber", controllers.SubscriberPost)

		// 链接管理
		authorized.GET("/link", controllers.LinkIndex)
		authorized.POST("/new_link", controllers.LinkCreate)
		authorized.POST("/link/:id/edit", controllers.LinkUpdate)
		authorized.POST("/link/:id/delete", controllers.LinkDelete)

		// 评论管理
		authorized.POST("/comment/:id", controllers.CommentRead)
		authorized.POST("/read_all", controllers.CommentReadAll)

		// 备份与恢复
		authorized.POST("/backup", controllers.BackupPost)
		authorized.POST("/restore", controllers.RestorePost)

		// 邮件发送
		authorized.POST("/new_mail", controllers.SendMail)
		authorized.POST("/new_batchmail", controllers.SendBatchMail)
	}

	// 启动服务
	err = router.Run(system.GetConfiguration().Addr)
	if err != nil {
		seelog.Critical(err)
	}
}

// 设置模板函数和模板路径
func setTemplate(engine *gin.Engine) {

	funcMap := template.FuncMap{
		"dateFormat": helpers.DateFormat,
		"substring":  helpers.Substring,
		"isOdd":      helpers.IsOdd,
		"isEven":     helpers.IsEven,
		"truncate":   helpers.Truncate,
		"length":     helpers.Len,
		"add":        helpers.Add,
		"minus":      helpers.Minus,
		"listtag":    helpers.ListTag,
	}

	engine.SetFuncMap(funcMap)
	path := filepath.Join(helpers.GetCurrentDirectory(), system.GetConfiguration().ViewDir)
	fmt.Println("Loading templates from:", path)
	engine.LoadHTMLGlob(path)
}

// 设置会话中间件
func setSessions(router *gin.Engine) {
	config := system.GetConfiguration()
	store := cookie.NewStore([]byte(config.SessionSecret))
	store.Options(sessions.Options{HttpOnly: true, MaxAge: 7 * 86400, Path: "/"}) // 设置会话选项
	router.Use(sessions.Sessions("gin-session", store))
}

// 共享数据中间件，用于在每个请求中设置用户信息和注册功能状态
func SharedData() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		if uID := session.Get(controllers.SessionKey); uID != nil {
			user, err := models.GetUser(uID)
			if err == nil {
				c.Set(controllers.ContextUserKey, user)
			}
		}
		if system.GetConfiguration().SignupEnabled {
			c.Set("SignupEnabled", true)
		}
		c.Next()
	}
}

// 认证中间件，用于验证用户是否已登录，并可选择是否要求管理员权限
func AuthRequired(adminScope bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if user, _ := c.Get(controllers.ContextUserKey); user != nil {
			if u, ok := user.(*models.User); ok && (!adminScope || u.IsAdmin) {
				c.Next()
				return
			}
		}
		seelog.Warnf("用户未授权访问 %s", c.Request.RequestURI)
		c.HTML(http.StatusForbidden, "errors/error.html", gin.H{
			"message": "禁止访问！",
		})
		c.Abort()
	}
}
