package com.craft.userservice.user.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.craft.userservice.user.model.User;


public interface UserRepository extends MongoRepository<User, String>{
	Optional<User> findByEmail(String email);
	Optional<User> findByMobile(String mobile);
	Optional<User> findByUserName(String userName);
	
	boolean existsByEmail(String emString);
	boolean existsByMobile(String mobile);
	boolean existsByUserName(String userName);

}
