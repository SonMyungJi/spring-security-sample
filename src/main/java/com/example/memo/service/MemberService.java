package com.example.memo.service;

import com.example.memo.configuration.security.JwtUtil;
import com.example.memo.domain.entity.Member;
import com.example.memo.domain.model.AuthorizedMember;
import com.example.memo.dto.LoginRequest;
import com.example.memo.dto.SignupRequest;
import com.example.memo.repository.MemberRepository;
import java.time.LocalDateTime;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService {

	private final MemberRepository memberRepository;
	private final PasswordEncoder passwordEncoder;

	public void signup(SignupRequest signupRequest) {
		Member member = new Member(signupRequest.email(), signupRequest.name(),
			passwordEncoder.encode(signupRequest.password()), Set.of("ROLE_MEMBER"),
			LocalDateTime.now());

		memberRepository.save(member);
	}

	public String login(LoginRequest loginRequest) {
		Member member = memberRepository.findByEmail(loginRequest.email());
		if (member == null) {
			throw new UsernameNotFoundException(loginRequest.email());
		}

		if (!passwordEncoder.matches(loginRequest.password(), member.getPassword())) {
			throw new BadCredentialsException("잘못된 요청입니다. 아이디 또는 비밀번호를 확인해주세요.");
		}

		return JwtUtil.createTokenWithScheme(loginRequest.email());
	}
}
