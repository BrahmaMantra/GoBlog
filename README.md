# goBlog 
   域名正在备案...
- [示例地址](http://brahmamantragoblog.xyz/)

## 一、初衷
作为一名web开发程序员居然没有自己的博客，都不好意思对外宣称自己的开发web的。
以前也有写博客的习惯，但是都是用的现有的博客网站。

## 二、技术选型
1. gin:[gin](https://github.com/gin-gonic/gin)
2. orm:[gorm](https://github.com/go-gorm/gorm)
3. database:[SQLite](github.com/glebarez/sqlite)/[MySQL](https://gorm.io/driver/mysql)
4. 文件存储:[七牛云存储](https://www.qiniu.com/)
5. 配置文件 [go-toml](https://github.com/pelletier/go-toml)

## 三、项目结构
```
-goBlog
    |-conf 配置文件目录
    |-controllers 控制器目录
    |-helpders 公共方法目录
    |-models 数据库访问目录
    |-static 静态资源目录
        |-css css文件目录
        |-images 图片目录
        |-js js文件目录
        |-libs js类库
    |-system 系统配置文件加载目录
    |-tests 测试目录
    |-views 模板文件目录
    |-main.go 程序执行入口
```

## 四、运行项目
```
git clone
cd goBlog
go mod tidy
go run main.go
```

## 五、项目发布
1. 本地发布
   - 下载安装[goreleaser](https://github.com/goreleaser/goreleaser/releases)
   - 执行命令`goreleaser release --snapshot --clean`
2. Github Actions
   ```bash
   git tag "v0.0.2"
   git push origin v0.0.2
   ```
3. 部署文件清单
   - conf #配置文件目录
   - static #静态资源目录
   - views #模板目录
   - goBlog #可执行文件

## 六、使用方法
### 使用说明
#### 常规部署
1. 执行`go run main.go -g`或编译后执行`goBlog -g`生成示例配置文件`conf/conf.sample.toml` (示例配置文件均为系统默认配置，可全部删除仅保留自己所需配置)
2. 修改conf.toml，设置signup_enabled = true
3. 访问http://xxx.xxx/signup 注册管理员账号 
4. 修改conf.toml，设置signup_enabled = false

#### Docekr
1. 配置好conf后执行`docker build -t goblog .`
2. 运行`docker run -p 8090:8090 goblog`

### 注意事项
1. 图床切换（**需开启对应图床配置**）
   ```toml
   file_server = "smms"
   #file_server = "qiniu"
   ```
2. 如果需要保存图片到七牛云，请自行申请[七牛云存储空间](https://www.qiniu.com/)，并修改配置文件填写
    ```toml
   [qiniu]
   enabled = true
   accesskey = 'AK'
   secretkey = 'SK'
   fileserver = '自定义域名，例如https://example.com'
   bucket = 'goBlog'
   ```
3. 如果需要github登录评论功能请自行注册[github oauthapp](https://github.com/settings/developers)，并修改配置文件填写
    ```toml
   [github]
   enabled = true
   clientid = ''
   clientsecret = ''
   redirecturl = 'https://example.com/oauth2callback'
   ```
4. 如果需要使用邮件订阅功能，请自行填写
   ```toml
   [smtp]
   enabled = true
   username = '用户名'
   password = '密码'
   host = 'smtp.163.com:25'
   ```
5. GoLand运行时，修改`Run/Debug Configurations` > `Output Directory`选择到项目根目录，否则报模板目录找不到
6. 数据库切换，使用MySQL数据库时，请先创建`goBlog`数据库(数据库名自便，与配置文件一致即可)
   ```toml
   [database]
   dialect = 'sqlite'
   dsn = 'goBlog.db?_loc=Asia/Shanghai'
   #dialect = 'mysql'
   #dsn = 'root:mysql@/goBlog?charset=utf8&parseTime=True&loc=Asia%2FShanghai'
   ```

## 七、效果图
- ![alt text](screenshots/image-1.png)
- ![alt text](screenshots/image-2.png)
