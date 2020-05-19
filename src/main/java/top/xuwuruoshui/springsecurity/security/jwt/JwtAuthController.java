package top.xuwuruoshui.springsecurity.security.jwt;

import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import top.xuwuruoshui.springsecurity.utils.ResultVo;

import java.util.Map;

@RestController
public class JwtAuthController {

    private JwtAuthService jwtAuthService;

    public JwtAuthController(JwtAuthService jwtAuthService) {
        this.jwtAuthService = jwtAuthService;
    }

    @PostMapping("/authentication")
    public ResultVo login(@RequestBody Map<String,String> map){
        String username = map.get("username");
        String password = map.get("password");
        if (StringUtils.isEmpty(username) || StringUtils.isEmpty(password)) {
            return ResultVo.failed();
        }
        try {
            return ResultVo.getResultVo(jwtAuthService.login(username,password),null,200);
        } catch (Exception e) {
            return ResultVo.failed();
        }
    }

    @PutMapping("/refreshToken")
    public ResultVo refresh(@RequestHeader("${jwt.header}") String token){
        return ResultVo.getResultVo(jwtAuthService.refreshToken(token),null,200);
    }
}
