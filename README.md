# 1. HttpBasic模式
>**HttpBasic**模式，将用户名和密码使用**Base64**模式加密。例如：用户名:user,密码root,就会将`user:root`进行加密,得到`dXNlcjpyb290`
>
>HTTP请求使用Authorization作为Header，值为`Basic dXNlcjpyb290`发送到服务端
>
>服务器接受请求,被`BasicAuthenticationFilter`拦截，提取`Authorization`的Header值，再用Base64进行解码，最后将用户名和密码和解码的结果进行比对

# 2. FormLogin模式
- 客制化登录界面
- 加密
- 角色、资源权限控制(role不能和authorities一起用，分开用可以)
- 登录成功失败的处理

# 3. Session会话管理

- 创建Session方法
  - **always**：如果当前请求没有session存在，Spring Security创建一个session。
  - **ifRequired（默认）**： Spring Security在需要时才创建session
  - **never**： Spring Security将永远不会主动创建session，但是如果session已经存在，它将使用该session
  - **stateless**：Spring Security不会创建或使用任何session。适合于接口型的无状态应用，该方式节省资源

- 会话超时及处理

- 固话技术:防止非法获取session和cookie

- cookie:防止通过脚本获取cookie,以及限制使用http或者https来发送cookie
- 限制一个用户的登录数量

