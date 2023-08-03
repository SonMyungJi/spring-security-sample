package com.example.memo.configuration.security;

import com.example.memo.configuration.security.redis.RedisUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

//@Component
//@RequiredArgsConstructor
//public class TokenLogoutHandler implements LogoutHandler {
//
//    private final JwtUtil jwtUtil;
//    private final RedisUtil redisUtil;
//
//    @Override
//    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//        String token = jwtUtil.getTokenFromHeader(request);
//
//        // 유효하지 않은 토큰이면 로그아웃 거부
//        if (!jwtUtil.validateToken(token)) {
//            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
//            return;
//        }
//
//        redisUtil.addTokenToBlacklist(token);
//    }
//}
