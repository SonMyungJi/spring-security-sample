package com.example.memo.service;

import com.example.memo.configuration.security.JwtUtil;
import com.example.memo.configuration.security.redis.RedisUtil;
import com.example.memo.domain.entity.Member;
import com.example.memo.dto.LoginRequest;
import com.example.memo.dto.SignupRequest;
import com.example.memo.repository.MemberRepository;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class MemberService {

	private final MemberRepository memberRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtUtil jwtUtil;
	private final RedisUtil redisUtil;

	public void signup(SignupRequest signupRequest) {
		Member member = new Member(signupRequest.email(), signupRequest.name(),
				passwordEncoder.encode(signupRequest.password()), Set.of("ROLE_MEMBER"),
				LocalDateTime.now());

		memberRepository.save(member);
	}

	public void login(LoginRequest loginRequest, HttpServletResponse response) {
		Member member = memberRepository.findByEmail(loginRequest.email());
		if (member == null) {
			throw new UsernameNotFoundException(loginRequest.email());
		}

		if (!passwordEncoder.matches(loginRequest.password(), member.getPassword())) {
			throw new BadCredentialsException("잘못된 요청입니다. 아이디 또는 비밀번호를 확인해주세요.");
		}

		String token = jwtUtil.createTokenWithScheme(loginRequest.email());
		String refreshToken = jwtUtil.createRefreshTokenWithScheme(loginRequest.email());

		redisUtil.saveRefreshToken(member.getEmail(), refreshToken);

		response.addHeader("Authorization", token);
		addRefreshTokenCookie(response, refreshToken);
	}

	private void addRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
		// 새로운 Cookie 객체 생성
		Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);

		// 쿠키의 유효 기간 설정 (예: 1주일로 설정)
		refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60); // 1주일(초단위)

		// 쿠키 경로 설정 (예: 서버의 모든 경로에서 접근 가능하도록 설정)
		refreshTokenCookie.setPath("/");

		// HttpOnly 설정
		refreshTokenCookie.setHttpOnly(true);

		// Secure 설정 (HTTPS에서만 쿠키 전송)
//		refreshTokenCookie.setSecure(true);

		// 쿠키를 Response 객체에 추가
		response.addCookie(refreshTokenCookie);
	}

	public void logout(HttpServletRequest request) {
		String token = jwtUtil.getTokenFromHeader(request);
		Claims userInfo = jwtUtil.getUserInfoFromToken(token);
		String username = userInfo.getSubject();

		// refreshToken은 redis에서 삭제
		redisUtil.deleteRefreshToken(username);

		// accessToken은 redis의 blacklist에 저장
		redisUtil.addTokenToBlacklist(username, token);
	}
}
