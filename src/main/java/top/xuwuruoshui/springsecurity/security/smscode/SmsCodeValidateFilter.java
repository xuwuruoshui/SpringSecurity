package top.xuwuruoshui.springsecurity.security.smscode;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;
import top.xuwuruoshui.springsecurity.dao.MyUserDetailsServiceMapper;
import top.xuwuruoshui.springsecurity.pojo.User;
import top.xuwuruoshui.springsecurity.security.handler.MyAuthenticationFailureHandler;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Objects;

@Component
public class SmsCodeValidateFilter extends OncePerRequestFilter {

    @Resource
    MyUserDetailsServiceMapper myUserDetailsServiceMapper;

    @Resource
    MyAuthenticationFailureHandler myAuthenticationFailureHandler;

    @Override
    protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain filterChain)
            throws ServletException, IOException {
        if (request.getRequestURI().equals("/smslogin")
                && request.getMethod().equalsIgnoreCase("post")) {
            try {
                validate(new ServletWebRequest(request));

            }catch (AuthenticationException e){
                myAuthenticationFailureHandler.onAuthenticationFailure(
                        request,response,e);
                return;
            }
        }
        filterChain.doFilter(request,response);
    }

    private void validate(ServletWebRequest request) throws ServletRequestBindingException {
        HttpSession session = request.getRequest().getSession();
        SmsCode codeInSession = (SmsCode) session.getAttribute("sms_key");
        String codeInRequest = request.getParameter("smsCode");
        String mobileInRequest = request.getParameter("mobile");


        if(StringUtils.isEmpty(mobileInRequest)){
            throw new SessionAuthenticationException("手机号码不能为空！");
        }
        if(StringUtils.isEmpty(codeInRequest)){
            throw new SessionAuthenticationException("短信验证码不能为空！");
        }
        if(Objects.isNull(codeInSession)){
            throw new SessionAuthenticationException("短信验证码不存在！");
        }
        if(codeInSession.isExpired()){
            session.removeAttribute("sms_key");
            throw new SessionAuthenticationException("短信验证码已过期！");
        }
        if(!codeInSession.getCode().equals(codeInRequest)){
            throw new SessionAuthenticationException("短信验证码不正确！");
        }

        if(!codeInSession.getMobile().equals(mobileInRequest)){
            throw new SessionAuthenticationException("短信发送目标与该手机号不一致！");
        }

        User myUserDetails = myUserDetailsServiceMapper.findByUserName(mobileInRequest);
        if(Objects.isNull(myUserDetails)){
            throw new SessionAuthenticationException("您输入的手机号不是系统的注册用户");
        }

        session.removeAttribute("sms_key");
    }
}