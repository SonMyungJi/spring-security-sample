package com.example.memo.configuration.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@RequiredArgsConstructor
class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final JwtUtil jwtUtil;

	// AbstractAuthenticationProcessingFilter의 메서드를 override
	// doFilter에서 인증에 성공 -> successfulAuthentication
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException {
		// TODO : 올바른 인증 요청에 대한 결과로 jwt token 만들고, 검증한 후에 201 response로 해당 token 세팅하기

		if (!authResult.isAuthenticated()) {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		String tokenWithScheme = jwtUtil.createTokenWithScheme(authResult.getName());
		String jwtToken = jwtUtil.getToken(tokenWithScheme);

		if (!jwtUtil.validateToken(jwtToken)) {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		getRememberMeServices().loginSuccess(request, response, authResult);

		response.setStatus(HttpServletResponse.SC_CREATED);
		response.getWriter().write(jwtToken);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
		response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
	}
}
