package com.example.demo.repository;

import com.example.demo.documents.TokenDocument;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;
import java.util.Optional;


public interface TokenRepository extends MongoRepository<TokenDocument, String> {
    Optional<TokenDocument> findByToken(String token);

    List<TokenDocument> findAllValidTokenByUserId(String userId);

}
