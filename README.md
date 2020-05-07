# 1. HttpBasic模式
>**HttpBasic**模式，将用户名和密码使用**Base64**模式加密。例如：用户名:user,密码root,就会将`user:root`进行加密,得到`dXNlcjpyb290`
>
>HTTP请求使用Authorization作为Header，值为`Basic dXNlcjpyb290`发送到服务端
>
>服务器接受请求,被`BasicAuthenticationFilter`拦截，提取`Authorization`的Header值，再用Base64进行解码，最后将用户名和密码和解码的结果进行比对

# 2. FormLogin模式

111