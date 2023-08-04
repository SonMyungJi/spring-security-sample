package com.example.memo.domain.entity;

import com.example.memo.dto.PostRequest;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class Post {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column
    private String title;

    @ManyToOne
    @JoinColumn(name = "member_id")
    private Member member;

    public Post(PostRequest request, Member member) {
        this.title = request.getTitle();
        this.member = member;
    }
}
