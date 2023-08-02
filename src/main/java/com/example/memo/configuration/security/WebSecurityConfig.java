package com.example.memo.configuration.security;

import com.example.memo.repository.MemberRepository;
import com.example.memo.service.RememberMeService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

	private final JwtUtil jwtUtil;
	public static final String ROLE_MEMBER = "ROLE_MEMBER";
	private final AuthenticationConfiguration authenticationConfiguration;
	private final AuthorizedMemberProvider authorizedMemberProvider;
	private final RememberMeService rememberMeService;
	private final TokenLogoutHandler tokenLogoutHandler;

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}

	@Bean
	public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
		JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtUtil);
		filter.setAuthenticationManager(authenticationConfiguration.getAuthenticationManager());
		filter.setRememberMeServices(rememberMeService);
		return filter;
	}

	@Bean
	public JwtAuthorizationFilter jwtAuthorizationFilter() {
		return new JwtAuthorizationFilter(jwtUtil, authorizedMemberProvider);
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
				.httpBasic(AbstractHttpConfigurer::disable)
				.csrf(AbstractHttpConfigurer::disable)
				.formLogin(Customizer.withDefaults())
				.rememberMe(configurer -> configurer.rememberMeServices(rememberMeService))
				.sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(
						SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(httpRequests -> httpRequests
						.requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
						.requestMatchers("/api/members/**").permitAll()
						.anyRequest().authenticated())
//				.oauth2Login(Customizer.withDefaults());
				.logout((logout -> logout
						.logoutUrl("/api/members/logout")
						.invalidateHttpSession(true)
						.deleteCookies("jwt")
						.addLogoutHandler(tokenLogoutHandler)));

		httpSecurity.addFilterBefore(jwtAuthorizationFilter(), JwtAuthenticationFilter.class);

		return httpSecurity.build();
	}
}
