package com.example.memo.configuration.security;

import com.example.memo.configuration.security.redis.RedisUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Component
@RequiredArgsConstructor
public class TokenLogoutHandler implements LogoutHandler {
    private final RedisUtil redisUtil;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String token = extractTokenFromCookie(request);

        // 유효하지 않은 토큰이면 로그아웃 거부
        if (!JwtUtil.validateToken(token)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        redisUtil.addTokenToBlacklist(token);
    }

    private String extractTokenFromCookie(HttpServletRequest request) {
        String token = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            token = Arrays.stream(cookies).filter(cookie -> cookie.getName().equals("jwt")).findFirst()
                    .map(Cookie::getValue).orElse(null);
        }
        return token;
    }
}
