package com.example.memo.dto;

import com.example.memo.domain.entity.Post;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PostResponse {
    private Long id;
    private String title;
    private String username;

    public PostResponse(Post post) {
        this.id = post.getId();
        this.title = post.getTitle();
        this.username = post.getMember().getEmail();
    }
}
