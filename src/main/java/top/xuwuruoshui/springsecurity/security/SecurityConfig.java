package top.xuwuruoshui.springsecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()//禁用跨站脚本攻击
                .formLogin()
                .loginPage("/login.html")//用户未登录时，访问任何资源都跳转到该路径，即登录页面
                .loginProcessingUrl("/login")//form中action的地址，也就是处理认证请求的路径
                .usernameParameter("username")//form中用户名输入框input的name名，不修改的话默认
                .passwordParameter("password")//form中密码输入框input的namem名，不修改的话默认是password
                //.defaultSuccessUrl("/index")//登录成功后默认跳转的路径index
                .successHandler((request, response, authentication) -> {
                    response.setContentType("application/json;charset=utf-8");
                    RequestCache cache = new HttpSessionRequestCache();
                    SavedRequest savedRequest = cache.getRequest(request, response);
                    String url = savedRequest.getRedirectUrl();
                    response.sendRedirect(url);

                })//实现登陆后返回之前用户想访问的页面，需要手动实现AuthenticationSuccessHandler
                .and()
                .authorizeRequests()
                .antMatchers("/login.html","/login").permitAll()
                .antMatchers("/biz1","/biz2").hasAnyAuthority("ROLE_user","ROLE_admin")
                //.antMatchers("/syslog","/sysuser").hasAnyRole("admin")
                .antMatchers("/syslog").hasAnyAuthority("sys:log")
                .antMatchers("/sysuser").hasAnyAuthority("sys:user")
                .anyRequest().authenticated();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user")
                .password(passwordEncoder().encode("root"))
                .roles("user")
                .and()
                .withUser("admin")
                .password(passwordEncoder().encode("root"))
                .authorities("sys:log","sys:user","ROLE_admin")
                //.roles("admin")//role和authorities不能同时用
                .and()
                .passwordEncoder(passwordEncoder());//使用BCrypt加密
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        //开放静态资源
        web.ignoring().antMatchers("/css/**","/fonts/**","/img/**","/js/**");
    }
}