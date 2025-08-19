package com.craft.userservice.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.craft.userservice.model.User;

public interface UserRepository extends MongoRepository<User, String>{
	Optional<User> findByEmail(String email);
	boolean existsByEmail(String emString);

}
