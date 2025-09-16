package com.craft.userservice.jwt.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.craft.userservice.jwt.model.RefreshToken;

public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String>{
	
	Optional<RefreshToken> findByToken(String token);
	
	Optional<RefreshToken> findByTokenAndUserId(String token, String userId);
	
	long deleteByTokenAndUserId(String token, String userId);
	
    long deleteByUserId(String userId);

}
