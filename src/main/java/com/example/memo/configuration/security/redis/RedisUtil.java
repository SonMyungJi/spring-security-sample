package com.example.memo.configuration.security.redis;

import com.example.memo.configuration.security.JwtUtil;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class RedisUtil {

    private final JwtUtil jwtUtil;
    private final RedisTemplate<String, Object> redisTemplate;
    private final RedisTemplate<String, Object> redisBlacklistTemplate;

    public void saveRefreshToken(String username, String token) {
        redisTemplate.opsForValue().set(username, token);
    }

    public void deleteRefreshToken(String username) {
        redisTemplate.delete(username);
        System.out.println("RefreshToken 삭제 : " + username);
    }

    // 토큰의 남은 시간을 계산해 블랙리스트에 저장
    public void addTokenToBlacklist(String username, String token) {
        Claims claims = jwtUtil.getUserInfoFromToken(token);
        Date expiration = claims.getExpiration();
        long remainingTime = expiration.getTime() - System.currentTimeMillis();
        if (remainingTime > 0) {
            String blacklistKey = username + "blacklisted";
            redisBlacklistTemplate.opsForValue().set(blacklistKey, token, remainingTime, TimeUnit.MILLISECONDS);
        }
    }
}
