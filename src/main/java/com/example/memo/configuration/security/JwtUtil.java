package com.example.memo.configuration.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Date;

@Slf4j
@Component
public class JwtUtil {

	private final String AUTHORIZATION_HEADER = "Authorization";
	private final String AUTHORIZATION_KEY = "auth";
	private final String BEARER_PREFIX = "Bearer ";

	private final int VALUE_INDEX = 7;
	private final long TOKEN_DURATION = 60 * 60 * 1000L; // 60분

	private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
	private final Key key = Keys.secretKeyFor(signatureAlgorithm);


	public String createTokenWithScheme(String username) {
		Date now = new Date();
		String role = "ROLE_MEMBER";

		// (AUTHORIZATION_KEY, "ROLE_MEMBER")에서 "ROLE_MEMBER"는 value로 인식

		return BEARER_PREFIX +
			Jwts.builder()
				.setSubject(username) // 사용자 식별자값(ID)
				.claim(AUTHORIZATION_KEY, role) // 사용자 권한
				.setExpiration(new Date(now.getTime() + TOKEN_DURATION)) // 만료 시간
				.setIssuedAt(now) // 발급일
				.signWith(key, signatureAlgorithm) // 암호화 알고리즘
				.compact();
	}

	public String getToken(String tokenWithScheme) {
		if (tokenWithScheme.startsWith(BEARER_PREFIX)) {
			return tokenWithScheme.substring(VALUE_INDEX);
		}
		return null;
	}

	public String getTokenFromHeader(HttpServletRequest request) {
		String token = request.getHeader(AUTHORIZATION_HEADER);
		if (StringUtils.hasText(token) && token.startsWith(BEARER_PREFIX)) {
			return token.substring(VALUE_INDEX);
		}
		return null;
	}

	public boolean validateToken(String token) {
		try {
			// 토큰의 위변조, 만료 체크
			Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
			return true;
		} catch (SecurityException | MalformedJwtException e) {
			log.error("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.");
		} catch (ExpiredJwtException e) {
			log.error("Expired JWT token, 만료된 JWT token 입니다.");
		} catch (UnsupportedJwtException e) {
			log.error("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.");
		} catch (IllegalArgumentException e) {
			log.error("JWT claims is empty, 잘못된 JWT 토큰 입니다.");
		}
		return false;
	}

	public Claims getUserInfoFromToken(String token) {
		return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
	}


//	// 3. 추출
//	public Claims getUserInfoFromToken(String token) {
//		return getClaimsJws(token).getBody();
//	}
//
//	// 2. 해석
//	private static Jws<Claims> getClaimsJws(String token) {
//		return getBuild().parseClaimsJws(token);
//	}
//
//	// 1. 인증
//	private static JwtParser getBuild() {
//		return Jwts.parserBuilder().setSigningKey(key).build();
//	}
}
