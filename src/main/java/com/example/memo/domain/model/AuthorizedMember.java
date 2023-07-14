package com.example.memo.domain.model;

import com.example.memo.domain.entity.Member;

import java.util.Collections;
import lombok.Getter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

@Getter
public class AuthorizedMember extends User {
	private final Member member;

	public AuthorizedMember(@LoginMember Member member) {
		super(member.getEmail(), member.getPassword(),
			Collections.singletonList(new SimpleGrantedAuthority("ROLE_MEMBER")));
		this.member = member;
	}
}
