## 关于oauth2认证
1. 注册/signin路由，并且与controllers.SigninGet，controllers.SigninPost绑定
2. SigninGet发送200OK与auth/signin.html到前端，并且将配置信息传递给模板
3. 前端点击oauth2认证(views/auth/signin.html:69)后，跳转到/auth/github页面，执行controllers.AuthGet，随机生成一个uuid当作state到session，后续和authurl = fmt.Sprintf(cfg.Github.AuthUrl, cfg.Github.ClientId, uuid)一起生成authurl地址，然后重定向到github认证服务（比如https://github.com/login/oauth/authorize?client_id=xxxxxxx&scope=user:email&state=xxxxxxx）
4. github认证成功后，会post到我们的/oauth2callback，调用Oauth2Callback，获得code和state，其中state就是上面rand的uuid，判断是不是同一个请求，判断成功后从session里删除state保证安全，然后用token, err := exchangeTokenByCode(code)，目的是用code换回accessToken
5. exchangeTokenByCode：带着id,密钥,回调url,token_url和scope，通过auth库的oauth.Transport.Exchange(code)交换访问令牌，缓存到本地
6. 然后Oauth2Callback继续从令牌中获得UserInfo，创建info，以userinfo.Login作为唯一标识，加入到数据库，至此一个用户就创建完毕了

## 关于new一个page
1. 前端点击创建后，进入PostNew函数，返回前端一个post/new.html
2. 前端的博客写好后，调用后端postCreate创建一个page并且加入数据库，然后重定向到/admin/post

## InitDB
1. 在InitDB里面，利用gorm.Open和config的数据库打开对应数据库