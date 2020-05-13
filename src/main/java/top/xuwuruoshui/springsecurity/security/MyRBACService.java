package top.xuwuruoshui.springsecurity.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Component
public class MyRBACService {




    public boolean hasPermission(HttpServletRequest request, Authentication authentication){

        Object principal = authentication.getPrincipal();

        if(principal instanceof UserDetails){
            UserDetails userDetails = ((UserDetails)principal);

            //由于登录时已经获取过权限了,只需要从内存中拿来与请求的url比对即可
            List<GrantedAuthority> authorityList =
                    AuthorityUtils.commaSeparatedStringToAuthorityList(request.getRequestURI());
            return userDetails.getAuthorities().contains(authorityList.get(0));

        }
        return false;
    }
}
