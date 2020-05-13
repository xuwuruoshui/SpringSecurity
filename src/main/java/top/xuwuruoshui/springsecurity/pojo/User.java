package top.xuwuruoshui.springsecurity.pojo;

import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@Setter
public class User implements UserDetails {
    private String password;  //密码
    private String username;  //用户名
    private boolean accountNonExpired;   //是否没过期
    private boolean accountNonLocked;   //是否没被锁定
    private boolean credentialsNonExpired;  //是否没过期
    private boolean enabled;  //账号是否可用
    private Collection<? extends GrantedAuthority> authorities;  //用户的权限集合

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
