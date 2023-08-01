package com.example.memo.repository;

import com.example.memo.domain.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface MemberRepository extends JpaRepository<Member, String> {

	@Query("select m from Member m JOIN FETCH m.roles WHERE m.email = ?1")
	Member findByEmail(String email);
}
