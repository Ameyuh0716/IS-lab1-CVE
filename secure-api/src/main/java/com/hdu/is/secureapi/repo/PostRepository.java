package com.hdu.is.secureapi.repo;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.hdu.is.secureapi.domain.Post;

public interface PostRepository extends JpaRepository<Post, Long> {

    /**
     * The search term is a bound JPQL parameter (:q), never concatenated into the query string.
     * Spring Data binds it through a PreparedStatement, so quotes / SQL keywords stay data.
     */
    @Query("""
            select p from Post p
            where lower(p.title) like lower(concat('%', :q, '%'))
               or lower(p.body)  like lower(concat('%', :q, '%'))
            """)
    List<Post> search(@Param("q") String q);
}
