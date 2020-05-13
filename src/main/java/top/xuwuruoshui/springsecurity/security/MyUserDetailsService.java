package top.xuwuruoshui.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import top.xuwuruoshui.springsecurity.dao.MyUserDetailsServiceMapper;
import top.xuwuruoshui.springsecurity.pojo.User;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private MyUserDetailsServiceMapper myUserDetailsServiceMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

       /*1. 根据username获取用户信息*/
        User user =
                myUserDetailsServiceMapper.findByUserName(username);

        if(user == null){
            throw new UsernameNotFoundException("用户名不存在");
        }

        /*2. 权限列表获取*/
        //获得用户角色列表
        List<String> roleCodes =
                myUserDetailsServiceMapper.findRoleByUserName(username);
        //通过角色列表获取权限列表
        List<String> authorities =
                myUserDetailsServiceMapper.findAuthorityByRoleCodes(roleCodes);

        //为角色标识加上ROLE_前缀（Spring Security规范）
        roleCodes = roleCodes.stream()
                .map(rc -> "ROLE_" + rc )
                .collect(Collectors.toList());
        //角色是一种特殊的权限，所以合并
        authorities.addAll(roleCodes);


        /*3. 将权限列表转换为正确的形式*/
        //方法1:转成用逗号分隔的字符串
        user.setAuthorities(
                AuthorityUtils.commaSeparatedStringToAuthorityList(
                        String.join(",",authorities)
                )
        );

        //方法2: lambda
       /* List<GrantedAuthority> list = new ArrayList<>();
        authorities.forEach(role->{
            SimpleGrantedAuthority authority = new SimpleGrantedAuthority(role);
            list.add(authority);
        });
        myUserDetails.setAuthorities(list);*/


        return user;
    }
}
