package com.example.memo.service;

import com.example.memo.domain.entity.Post;
import com.example.memo.domain.model.AuthorizedMember;
import com.example.memo.dto.PostRequest;
import com.example.memo.dto.PostResponse;
import com.example.memo.repository.PostRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PostService {

    private final PostRepository postRepository;

    public PostResponse createPost(PostRequest request, AuthorizedMember member) {
        Post post = postRepository.save(new Post(request, member.getMember()));
        return new PostResponse(post);
    }
}
