package top.xuwuruoshui.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //注入
    private final MyUserDetailsService myUserDetailsService;
    //被挤下线后的操作
    private final MySessionInformationExpiredStrategy mySessionInformationExpiredStrategy;



    public SecurityConfig(MyUserDetailsService myUserDetailsService, MySessionInformationExpiredStrategy mySessionInformationExpiredStrategy ) {
        this.myUserDetailsService = myUserDetailsService;
        this.mySessionInformationExpiredStrategy = mySessionInformationExpiredStrategy;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()//禁用跨站脚本攻击
                .formLogin()
                .loginPage("/login.html")//用户未登录时，访问任何资源都跳转到该路径，即登录页面
                .loginProcessingUrl("/login")//form中action的地址，也就是处理认证请求的路径
                .usernameParameter("username")//form中用户名输入框input的name名，不修改的话默认
                .passwordParameter("password")//form中密码输入框input的namem名，不修改的话默认是password
                //.defaultSuccessUrl("/index")//登录成功后默认跳转的路径index
                .successHandler(new SavedRequestAwareAuthenticationSuccessHandler())
                .and()
                .authorizeRequests()
                .antMatchers("/login.html","/login").permitAll()
                .antMatchers("/index","/").authenticated()
                .anyRequest().access("@myRBACService.hasPermission(request,authentication)")
                .and()
                .rememberMe()//记住我模式开启
                .rememberMeParameter("remember-you")//客制化remember me的参数
                .rememberMeCookieName("rememberCookie")//客制化cookiei名字
                .tokenValiditySeconds(2 * 24 * 60 * 60)//token过期时期2天
                .tokenRepository(persistentTokenRepository())//cookie存数据库,重启应用cookie任然管用
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

    //持久化cookie到数据库
    @Autowired
    private DataSource dataSource;
    @Bean
    public PersistentTokenRepository persistentTokenRepository(){
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
        return tokenRepository;
    }


    @Override
    public void configure(WebSecurity web) throws Exception {
        //开放静态资源
        web.ignoring().antMatchers("/css/**","/fonts/**","/img/**","/js/**");
    }
}