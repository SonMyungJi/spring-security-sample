package com.example.memo.controller.api;

import com.example.memo.domain.entity.Member;
import com.example.memo.domain.model.AuthorizedMember;
import com.example.memo.domain.model.getAuthMember;
import com.example.memo.dto.LoginRequest;
import com.example.memo.dto.MemberInfo;
import com.example.memo.dto.SignupRequest;
import com.example.memo.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/members")
@RequiredArgsConstructor
public class MemberController {

	private final MemberService memberService;

	@PostMapping("/signup")
	public ResponseEntity<String> signup(@RequestBody SignupRequest signupRequest) {
		memberService.signup(signupRequest);
		return ResponseEntity.status(201).body("Signup Succeeded");
	}

	@PostMapping("")
	public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest) {
		return ResponseEntity.ok(memberService.login(loginRequest));
	}

	@GetMapping("")
	public ResponseEntity<MemberInfo> getMemberInfo(@getAuthMember AuthorizedMember authorizedMember) {
		if (authorizedMember == null) {
			return ResponseEntity.badRequest().build();
		}

		// TODO : authorizedMember.getMember()와 같은 중복 개념 접근 개선하기
		Member member = authorizedMember.getMember();
		return ResponseEntity.ok(new MemberInfo(member.getEmail(), member.getName(), member.getRoles()));
	}
}
