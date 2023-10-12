package study.springsecurity.practice.domain.dto;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import study.springsecurity.practice.domain.enums.Role;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Getter
public class OAuth2CustomUser extends DefaultOAuth2User {
    private String email;
    private Role role;

    public OAuth2CustomUser(Collection<? extends GrantedAuthority> authorities,
                            Map<String, Object> attributes, String nameAttributeKey,
                            String email, Role role) {
        super(authorities, attributes, nameAttributeKey);
        this.email = email;
        this.role = role;
    }

    @Override
    public String toString() {
        return "OAuth2CustomUser{" +
                "email='" + email + '\'' +
                ", role=" + role +
                '}';
    }
}
