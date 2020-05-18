package top.xuwuruoshui.springsecurity.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.stereotype.Component;
import top.xuwuruoshui.springsecurity.utils.ResultVo;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {


        response.setContentType("application/json;charset=UTF-8");

        if(exception instanceof SessionAuthenticationException){
            response.getWriter().write(objectMapper.writeValueAsString(ResultVo.getResultVo(exception.getMessage(),null,401)));
            return;
        }
        response.getWriter().write(objectMapper.writeValueAsString(ResultVo.failed()));
    }
}
