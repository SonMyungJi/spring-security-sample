package com.example.memo.configuration.security.redis;

import com.example.memo.configuration.security.JwtUtil;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class RedisUtil {

    private final RedisTemplate<String, Object> redisTemplate;

    private final RedisTemplate<String, Object> redisBlacklistTemplate;

    public void saveRefreshToken(String username, String token) {
        redisTemplate.opsForValue().set(username, token);
    }

    public void deleteRefreshToken(String username) {
        redisTemplate.delete(username);
        System.out.println("RefreshToken 삭제 : " + username);
    }

    public String getRefreshToken(String token) {
        Set<String> keys = redisTemplate.keys("*");
        if (keys == null || keys.isEmpty()) {
            return null;
        }

        for (String key : keys) {
            String value = (String) redisTemplate.opsForValue().get(key);
            if (value != null && value.equals(token)) {
                return key;
            }
        }

        return null;
    }


    // 토큰의 남은 시간을 계산해 블랙리스트에 저장
    public void addTokenToBlacklist(String username, String token) {
        Claims claims = JwtUtil.getUserInfoFromToken(token);
        Date expiration = claims.getExpiration();
        long remainingTime = expiration.getTime() - System.currentTimeMillis();
        if (remainingTime > 0) {
            String blacklistKey = username + "blacklisted";
            redisBlacklistTemplate.opsForValue().set(blacklistKey, token, remainingTime, TimeUnit.MILLISECONDS);
        }
    }
}
