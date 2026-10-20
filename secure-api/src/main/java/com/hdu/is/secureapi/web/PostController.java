package com.hdu.is.secureapi.web;

import java.net.URI;
import java.util.List;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.hdu.is.secureapi.dto.CreatePostRequest;
import com.hdu.is.secureapi.dto.PostView;
import com.hdu.is.secureapi.security.InputValidator;
import com.hdu.is.secureapi.service.PostService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/posts")
public class PostController {

    private final PostService postService;

    @SuppressFBWarnings(value = "EI_EXPOSE_REP2",
            justification = "Spring-managed singleton injected by the container; not externally mutable state")
    public PostController(PostService postService) {
        this.postService = postService;
    }

    @GetMapping
    public ResponseEntity<List<PostView>> list(@RequestParam(name = "q", required = false) String q) {
        if (q == null) {
            return ResponseEntity.ok(postService.findAll());
        }
        if (!InputValidator.isValidSearchTerm(q)) {
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.ok(postService.search(q));
    }

    @PostMapping
    public ResponseEntity<PostView> create(@Valid @RequestBody CreatePostRequest request, Authentication authentication) {
        PostView created = postService.create(request, authentication.getName());
        return ResponseEntity.created(URI.create("/api/posts/" + created.id())).body(created);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable("id") Long id) {
        postService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
