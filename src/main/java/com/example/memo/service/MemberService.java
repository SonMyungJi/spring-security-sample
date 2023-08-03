package com.example.memo.service;

import com.example.memo.configuration.security.JwtUtil;
import com.example.memo.configuration.security.redis.RedisUtil;
import com.example.memo.domain.entity.Member;
import com.example.memo.dto.LoginRequest;
import com.example.memo.dto.SignupRequest;
import com.example.memo.repository.MemberRepository;
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
		response.addHeader("Authorization", token);
	}

	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		String token = jwtUtil.getTokenFromHeader(request);

		// 유효하지 않은 토큰은 authentication부터 안 만들어짐

		redisUtil.addTokenToBlacklist(token);
	}
}
