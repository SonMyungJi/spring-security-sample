package com.example.memo.configuration.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static com.example.memo.configuration.security.WebSecurityConfig.ROLE_MEMBER;

@RequiredArgsConstructor
class JwtAuthorizationFilter extends OncePerRequestFilter {

	private final JwtUtil jwtUtil;
	private final AuthorizedMemberProvider authorizedMemberProvider;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
									FilterChain filterChain) throws ServletException, IOException {
		// TODO : 요청에 들어온 JWT를 parsing해서 "ROLE_MEMBER" 권한이 있는지 확인하고, SecurityContextHolder에 context 설정하기
		String jwtToken = jwtUtil.getTokenFromHeader(request);

		if (!StringUtils.isEmpty(jwtToken)) {
			if (!jwtUtil.validateToken(request, response, jwtToken)) {
				return;
			}
			Claims userInfo = jwtUtil.getUserInfoFromToken(jwtToken);
			String authority = (String) userInfo.get("auth");

			if (ROLE_MEMBER.equals(authority)) {
				String username = userInfo.getSubject();
				UserDetails authorizedMember = authorizedMemberProvider.loadUserByUsername(username);
				Authentication authentication = new UsernamePasswordAuthenticationToken(authorizedMember,
						authorizedMember.getPassword(), authorizedMember.getAuthorities());
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		}

		filterChain.doFilter(request, response);
	}

}
