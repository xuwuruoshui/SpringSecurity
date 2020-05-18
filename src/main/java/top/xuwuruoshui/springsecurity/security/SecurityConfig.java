package top.xuwuruoshui.springsecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import top.xuwuruoshui.springsecurity.security.handler.MyAuthenticationFailureHandler;
import top.xuwuruoshui.springsecurity.security.handler.MyAuthenticationSuccessHandler;
import top.xuwuruoshui.springsecurity.security.smscode.SmsCodeSecurityConfig;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //注入
    private final MyUserDetailsService myUserDetailsService;
    //被挤下线后的操作
    private final MySessionInformationExpiredStrategy mySessionInformationExpiredStrategy;
    private final MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;
    private final MyAuthenticationFailureHandler myAuthenticationFailureHandler;
    private final SmsCodeSecurityConfig smsCodeSecurityConfig;



    public SecurityConfig(MyUserDetailsService myUserDetailsService, MySessionInformationExpiredStrategy mySessionInformationExpiredStrategy, MyAuthenticationSuccessHandler myAuthenticationSuccessHandler, MyAuthenticationFailureHandler myAuthenticationFailureHandler, SmsCodeSecurityConfig smsCodeSecurityConfig) {
        this.myUserDetailsService = myUserDetailsService;
        this.mySessionInformationExpiredStrategy = mySessionInformationExpiredStrategy;
        this.myAuthenticationSuccessHandler = myAuthenticationSuccessHandler;
        this.myAuthenticationFailureHandler = myAuthenticationFailureHandler;
        this.smsCodeSecurityConfig = smsCodeSecurityConfig;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()//禁用跨站脚本攻击
                .formLogin()
                .loginPage("/login.html")//用户未登录时，访问任何资源都跳转到该路径，即登录页面
                .successHandler(myAuthenticationSuccessHandler)
                .failureHandler(myAuthenticationFailureHandler)
                .and()
                .apply(smsCodeSecurityConfig)//启用自定义的短信验证码拦截器
                .and()
                .authorizeRequests()
                .antMatchers("/login.html","/smscode","/smslogin").permitAll()
                .antMatchers("/index","/").authenticated()
                .anyRequest().access("@myRBACService.hasPermission(request,authentication)")
                .and()
                .rememberMe()//记住我模式开启
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)//always ifRequired(默认) never stateless
                .invalidSessionUrl("/index")//会话超时
                .maximumSessions(1)//一个用户在线数为1
                .maxSessionsPreventsLogin(false)//false,挤掉之前登录的 true,登录过了,其他地方不能登录
                .expiredSessionStrategy(mySessionInformationExpiredStrategy);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //从数据库中获取
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