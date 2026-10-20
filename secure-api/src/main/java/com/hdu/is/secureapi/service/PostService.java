package com.hdu.is.secureapi.service;

import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.hdu.is.secureapi.domain.Post;
import com.hdu.is.secureapi.dto.CreatePostRequest;
import com.hdu.is.secureapi.dto.PostView;
import com.hdu.is.secureapi.exception.NotFoundException;
import com.hdu.is.secureapi.repo.PostRepository;
import com.hdu.is.secureapi.security.XssSanitizer;

@Service
public class PostService {

    private final PostRepository postRepository;

    public PostService(PostRepository postRepository) {
        this.postRepository = postRepository;
    }

    @Transactional(readOnly = true)
    public List<PostView> findAll() {
        return postRepository.findAll().stream().map(this::toView).toList();
    }

    @Transactional(readOnly = true)
    public List<PostView> search(String term) {
        return postRepository.search(term == null ? "" : term).stream().map(this::toView).toList();
    }

    /**
     * User supplied text is HTML-escaped before it is stored, so every later read is safe
     * without relying on the client to escape it.
     */
    @Transactional
    public PostView create(CreatePostRequest request, String author) {
        Post post = new Post(
                XssSanitizer.escape(request.title()),
                XssSanitizer.escape(request.body()),
                XssSanitizer.escape(author));
        return toView(postRepository.save(post));
    }

    @Transactional
    public void delete(Long id) {
        if (!postRepository.existsById(id)) {
            throw new NotFoundException("Post " + id + " not found");
        }
        postRepository.deleteById(id);
    }

    private PostView toView(Post post) {
        return new PostView(post.getId(), post.getTitle(), post.getBody(), post.getAuthor(), post.getCreatedAt());
    }
}
