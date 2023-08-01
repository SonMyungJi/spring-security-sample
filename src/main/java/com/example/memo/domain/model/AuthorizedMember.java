package com.example.memo.domain.model;

import com.example.memo.domain.entity.Member;
import lombok.Getter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collections;

import static com.example.memo.configuration.security.WebSecurityConfig.ROLE_MEMBER;

// spring security와 결합된 새로운 데이터 -> entity와 구분
@Getter
public class AuthorizedMember extends User {
    private final Member member;

    public AuthorizedMember(Member member) {
        super(member.getEmail(), member.getPassword(), Collections.singletonList(new SimpleGrantedAuthority(ROLE_MEMBER)));
        this.member = member;
    }
}
