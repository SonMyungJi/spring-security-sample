package com.example.memo.configuration.security.redis;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

// 실제로 데이터를 redis에 저장하고 가져옴
@Configuration
public class RedisTemplateConfig {
    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder restTemplateBuilder) {
        return restTemplateBuilder
                // restTemplate로 외부 API 호출시 일정 시간이 지나도 응답이 없을 때 무한 대기 방지를 위한 강제 종료
                .setConnectTimeout(Duration.ofSeconds(5)) // 5초
                .setReadTimeout(Duration.ofSeconds(5)) // 5초
                .build();
    }
}
