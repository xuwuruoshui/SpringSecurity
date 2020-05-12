package top.xuwuruoshui.springsecurity.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyUserDetailsService myUserDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()//禁用跨站脚本攻击
                .formLogin()
                .loginPage("/login.html")//用户未登录时，访问任何资源都跳转到该路径，即登录页面
                .loginProcessingUrl("/login")//form中action的地址，也就是处理认证请求的路径
                .usernameParameter("username")//form中用户名输入框input的name名，不修改的话默认
                .passwordParameter("password")//form中密码输入框input的namem名，不修改的话默认是password
                //.defaultSuccessUrl("/index")//登录成功后默认跳转的路径index
                .successHandler(new SavedRequestAwareAuthenticationSuccessHandler())//实现登陆后返回之前用户想访问的页面，需要手动实现AuthenticationSuccessHandler
                .and()
                .authorizeRequests()
                .antMatchers("/login.html","/login","/timeout.html").permitAll()
                .antMatchers("/biz1","/biz2").hasAnyAuthority("ROLE_user","ROLE_admin")
                //.antMatchers("/syslog","/sysuser").hasAnyRole("admin")
                .antMatchers("/syslog").hasAnyAuthority("/syslog")
                .antMatchers("/sysuser").hasAnyAuthority("/sysuser")
                .anyRequest().authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)//always ifRequired(默认) never stateless
                .invalidSessionUrl("/index")//会话超时
                .maximumSessions(1)//一个用户在线数为1
                .maxSessionsPreventsLogin(false)//false,挤掉之前登录的 true,登录过了,其他地方不能登录
                .expiredSessionStrategy(new SessionInformationExpiredStrategy() {
                    //jackson的JSON处理对象
                    private ObjectMapper objectMapper = new ObjectMapper();
                    @Override
                    public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException, ServletException {
                        Map<String, Object> map = new HashMap<>();
                        map.put("code", 0);
                        map.put("msg", "您的登录已经超时或者已经在另一台机器登录，您被迫下线。"
                                + event.getSessionInformation().getLastRequest());

                        // Map -> Json
                        String json = objectMapper.writeValueAsString(map);

                        //输出JSON信息的数据
                        event.getResponse().setContentType("application/json;charset=UTF-8");
                        event.getResponse().getWriter().write(json);

                        // 或者是跳转html页面，url代表跳转的地址
                        // redirectStrategy.sendRedirect(event.getRequest(), event.getResponse(), "url");
                    }
                });
        //他自己实现的SimpleXXX属实垃圾只能跳转url,不如手动实现一个登录过期的策略,可以返回JSON也可以跳转url
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
/*        auth.inMemoryAuthentication()
                .withUser("user")
                .password(passwordEncoder().encode("root"))
                .roles("user")
                .and()
                .withUser("admin")
                .password(passwordEncoder().encode("root"))
                .authorities("sys:log","sys:user","ROLE_admin")
                //.roles("admin")//role和authorities不能同时用
                .and()
                .passwordEncoder(passwordEncoder());//使用BCrypt加密*/
        auth.userDetailsService(myUserDetailsService).passwordEncoder(passwordEncoder());
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