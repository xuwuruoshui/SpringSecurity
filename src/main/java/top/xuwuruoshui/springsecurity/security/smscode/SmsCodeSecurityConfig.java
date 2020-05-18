package top.xuwuruoshui.springsecurity.security.smscode;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import top.xuwuruoshui.springsecurity.security.MyUserDetailsService;
import top.xuwuruoshui.springsecurity.security.handler.MyAuthenticationFailureHandler;
import top.xuwuruoshui.springsecurity.security.handler.MyAuthenticationSuccessHandler;

@Component
public class SmsCodeSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;
    private final MyAuthenticationFailureHandler myAuthenticationFailureHandler;
    private final MyUserDetailsService myUserDetailsService;
    private final SmsCodeValidateFilter smsCodeValidateFilter;

    public SmsCodeSecurityConfig(MyAuthenticationSuccessHandler myAuthenticationSuccessHandler, MyAuthenticationFailureHandler myAuthenticationFailureHandler, MyUserDetailsService myUserDetailsService, SmsCodeValidateFilter smsCodeValidateFilter) {
        this.myAuthenticationSuccessHandler = myAuthenticationSuccessHandler;
        this.myAuthenticationFailureHandler = myAuthenticationFailureHandler;
        this.myUserDetailsService = myUserDetailsService;
        this.smsCodeValidateFilter = smsCodeValidateFilter;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {

        SmsCodeAuthenticationFilter smsCodeAuthenticationFilter = new SmsCodeAuthenticationFilter();
        smsCodeAuthenticationFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        smsCodeAuthenticationFilter.setAuthenticationSuccessHandler(myAuthenticationSuccessHandler);
        smsCodeAuthenticationFilter.setAuthenticationFailureHandler(myAuthenticationFailureHandler);

        // 获取验证码提供者
        SmsCodeAuthenticationProvider smsCodeAuthenticationProvider = new SmsCodeAuthenticationProvider();
        smsCodeAuthenticationProvider.setUserDetailsService(myUserDetailsService);

        //在用户密码过滤器前面加入短信验证码校验过滤器
        http.addFilterBefore(smsCodeValidateFilter, UsernamePasswordAuthenticationFilter.class);

        http.authenticationProvider(smsCodeAuthenticationProvider);
        //在用户密码过滤器后面加入短信验证码认证授权过滤器        
        http.addFilterAfter(smsCodeAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

    }
}