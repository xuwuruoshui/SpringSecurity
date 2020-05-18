package top.xuwuruoshui.springsecurity.security.smscode;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import top.xuwuruoshui.springsecurity.dao.MyUserDetailsServiceMapper;
import top.xuwuruoshui.springsecurity.pojo.User;
import top.xuwuruoshui.springsecurity.security.handler.MyAuthenticationFailureHandler;
import top.xuwuruoshui.springsecurity.utils.ResultVo;

import javax.annotation.Resource;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Slf4j
@RestController
public class SmsController {

    @Resource
    MyUserDetailsServiceMapper myUserDetailsServiceMapper;
    @Resource
    MyAuthenticationFailureHandler myAuthenticationFailureHandler;


    //获取短信验证码
    @GetMapping("/smscode")
    public ResultVo sms(String mobile, HttpSession session) throws IOException {

        User userDetails = myUserDetailsServiceMapper.findByUserName(mobile);

        //未查询到手机号
        if(userDetails == null){
            return ResultVo.getResultVo("未查询到手机号",null,401);
        }


        SmsCode smsCode = new SmsCode(
                RandomStringUtils.randomNumeric(4),60,mobile);
        //TODO 此处调用验证码发送服务接口
        log.info(smsCode.getCode() + "=》" + mobile);
        session.setAttribute("sms_key",smsCode);

        return ResultVo.getResultVo("查询成功",null,200);
    }
}
