package com.example.memo.configuration.security.redis;

import com.example.memo.configuration.security.JwtUtil;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class RedisUtil {

    private final RedisTemplate<String, Object> redisTemplate;
    public static final RedisTemplate<String, Object> redisBlacklistTemplate = new RedisTemplate<>();

    // 토큰의 남은 시간을 계산해 블랙리스트에 저장
    public void addTokenToBlacklist(String token) {
        long remainingTime = JwtUtil.getUserInfoFromToken(token).getExpiration().getTime()
                - System.currentTimeMillis();
        redisBlacklistTemplate.opsForValue().set("blacklisted", token, remainingTime, TimeUnit.MILLISECONDS);
    }

}
