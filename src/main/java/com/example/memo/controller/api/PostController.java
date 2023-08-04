package com.example.memo.controller.api;

import com.example.memo.domain.model.AuthorizedMember;
import com.example.memo.dto.PostRequest;
import com.example.memo.dto.PostResponse;
import com.example.memo.service.PostService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class PostController {
    private final PostService postService;

    @PostMapping("/posts")
    public ResponseEntity<PostResponse> createPost(@RequestBody PostRequest request, @AuthenticationPrincipal AuthorizedMember member) {
        PostResponse result = postService.createPost(request, member);
        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }
}
