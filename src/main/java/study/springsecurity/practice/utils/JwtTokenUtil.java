package study.springsecurity.practice.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtTokenUtil implements InitializingBean {

    @Value("${jwt.token.secret.access-token}")
    private String accessTokenSecret;
    @Value("${jwt.token.secret.refresh-token}")
    private String refreshTokenSecret;
    @Value("${jwt.expireTimeMs}")
    private long expireTimeMs;
    private Key accessKey;
    private Key refreshKey;

    // 빈이 생성되고 주입을 받은 후에 secret 값을 Base64 Decode해서 key 변수에 할당
    @Override
    public void afterPropertiesSet() throws Exception {
        byte[] accessKeyBytes = Decoders.BASE64.decode(accessTokenSecret);
        byte[] refreshKeyBytes = Decoders.BASE64.decode(refreshTokenSecret);
        this.accessKey = Keys.hmacShaKeyFor(accessKeyBytes);
        this.refreshKey = Keys.hmacShaKeyFor(refreshKeyBytes);
    }

    public String createAccessToken(String email) {

        return Jwts.builder()
                .setSubject(email)
                .setExpiration(new Date(System.currentTimeMillis() + expireTimeMs))
                .signWith(accessKey, SignatureAlgorithm.HS512)
                .compact();
    }

    public String createRefreshToken(String email) {

        return Jwts.builder()
                .setSubject(email)
                .setExpiration(new Date(System.currentTimeMillis() + expireTimeMs))
                .signWith(refreshKey, SignatureAlgorithm.HS512)
                .compact();
    }
}
