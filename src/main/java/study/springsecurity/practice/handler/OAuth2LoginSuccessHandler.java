package study.springsecurity.practice.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;
import study.springsecurity.practice.domain.dto.OAuth2CustomUser;
import study.springsecurity.practice.utils.JwtTokenUtil;

import java.io.IOException;
import java.net.URI;
@Slf4j
@RequiredArgsConstructor
@Component
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {
    private final JwtTokenUtil jwtTokenUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("AuthenticationSuccess 시작");
        OAuth2CustomUser oAuth2User = (OAuth2CustomUser) authentication.getPrincipal();

        String email = oAuth2User.getEmail(); // OAuth2User로부터 Resource Owner의 이메일 주소를 얻음

        redirect(request, response, email); // Access Token과 Refresh Token을 Frontend에 전달하기 위해 Redirect
    }

    private void redirect(HttpServletRequest request, HttpServletResponse response, String email) throws IOException {
        log.info("Token 생성 시작");
        String accessToken = jwtTokenUtil.createAccessToken(email);
        String refreshToken = jwtTokenUtil.createRefreshToken(email);

        String redirectUrl = createRedirectUrl(accessToken, refreshToken);
        response.sendRedirect(redirectUrl);
    }

    private String createRedirectUrl(String accessToken, String refreshToken) {
        // 파라미터 추가
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString("http://localhost:3001/home")
                .queryParam("access_token", accessToken)
                .queryParam("refresh_token", refreshToken);

        return builder.toUriString();
    }
}
