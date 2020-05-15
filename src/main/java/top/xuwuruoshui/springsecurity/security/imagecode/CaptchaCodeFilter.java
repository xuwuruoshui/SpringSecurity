package top.xuwuruoshui.springsecurity.security.imagecode;

import com.google.code.kaptcha.Constants;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;
import org.thymeleaf.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Objects;

@Component
public class CaptchaCodeFilter extends OncePerRequestFilter {
    private final AuthenticationFailureHandler authenticationFailureHandler= new AuthenticationFailureHandler(){

        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

            if(exception instanceof SessionAuthenticationException) {
                logger.info("验证码错误");
                response.sendRedirect("/login.html");
            }
        }
    };


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(StringUtils.equals("/login",request.getRequestURI()) && StringUtils.equalsIgnoreCase(request.getMethod(),"post")){
            //验证 验证码是否与用户输入匹配
            try{
                //1.验证谜底与用户输入是否匹配
                validate(new ServletWebRequest(request));
            }catch(AuthenticationException e){
                //2.捕获步骤1中校验出现异常，交给失败处理类进行进行处理
                authenticationFailureHandler.onAuthenticationFailure(request,response,e);
                return;
            }
        }

        filterChain.doFilter(request,response);
    }

    private void validate(ServletWebRequest request){
        HttpSession session = request.getRequest().getSession();
        try {
            String codeInRequest = ServletRequestUtils.getStringParameter(request.getRequest(), "captchaCode");
            if(StringUtils.isEmpty(codeInRequest)){
                throw new SessionAuthenticationException("验证码不能为空");
            }
            // 获取session池中的验证码谜底
            CaptchaImageVO codeInSession = (CaptchaImageVO)
                    session.getAttribute(Constants.KAPTCHA_SESSION_KEY);
            if(Objects.isNull(codeInSession)) {
                throw new SessionAuthenticationException("您输入的验证码不存在");
            }

            // 校验服务器session池中的验证码是否过期
            if(codeInSession.isExpried()) {
                session.removeAttribute(Constants.KAPTCHA_SESSION_KEY);
                throw new SessionAuthenticationException("验证码已经过期");
            }

            // 请求验证码校验
            if(!StringUtils.equals(codeInSession.getCode(), codeInRequest)) {
                throw new SessionAuthenticationException("验证码不匹配");
            }
        } catch (ServletRequestBindingException e) {
            e.printStackTrace();
        }

    }
}
