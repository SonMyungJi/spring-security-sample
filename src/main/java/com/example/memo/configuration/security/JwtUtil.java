package com.example.memo.configuration.security;

import com.example.memo.configuration.security.redis.RedisUtil;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Date;
import java.util.UUID;

@Slf4j
@Component
public class JwtUtil {

	private final String AUTHORIZATION_HEADER = "Authorization";
	private final String AUTHORIZATION_KEY = "auth";
	private final String BEARER_PREFIX = "Bearer ";

	private final int VALUE_INDEX = 7;
	private final long TOKEN_DURATION = 1 * 60 * 1000L; // 30분
	private final long REFRESHTOKEN_DURATION = 7 * 24 * 60 * 60 * 1000L;

	private static final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
	private static final Key key = Keys.secretKeyFor(signatureAlgorithm);

	private final RedisUtil redisUtil;

	public JwtUtil(RedisUtil redisUtil) {
		this.redisUtil = redisUtil;
	}


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

	public String createRefreshTokenWithScheme(String username) {
		Date now = new Date();

		// 불필요한 사용자 정보 삭제
		return Jwts.builder()
				.setSubject(UUID.nameUUIDFromBytes(username.getBytes()).toString().replace("-", "")) // 사용자 식별자값(UUID)
				.setExpiration(new Date(now.getTime() + REFRESHTOKEN_DURATION)) // 만료 시간
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

	public String getTokenFromCookie(HttpServletRequest request) {
		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if ("refreshToken".equals(cookie.getName())) {
					return cookie.getValue();
				}
			}
		}
		return null;
	}

	public boolean validateToken(HttpServletRequest request, HttpServletResponse response, String token) {
		try {
			// 토큰의 위변조, 만료 체크
			Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
			return true;

		} catch (ExpiredJwtException e) {
			log.error("Expired JWT token, 만료된 JWT token 입니다.");
			handleExpiredToken(request, response);

		} catch (SecurityException | MalformedJwtException e) {
			log.error("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.");
		} catch (UnsupportedJwtException e) {
			log.error("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.");
		} catch (IllegalArgumentException e) {
			log.error("JWT claims is empty, 잘못된 JWT 토큰 입니다.");
		} catch (Exception e) {
			log.error("토큰 예외 발생");
		}
		return false;
	}

	public void handleExpiredToken(HttpServletRequest request, HttpServletResponse response) {
		String refreshToken = getTokenFromCookie(request);
		if (refreshToken != null) {
			String username = redisUtil.getRefreshToken(refreshToken);
			String newToken = createTokenWithScheme(username);
			response.addHeader("Authorization", newToken);
		}
	}

	public static Claims getUserInfoFromToken(String token) {
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
