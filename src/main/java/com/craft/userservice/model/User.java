package com.craft.userservice.model;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import com.craft.userservice.enums.Role;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Document(collection = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
	@Id
	private String id;

	@Indexed(unique = true)
	private String email;
	private String password;
	private Set<Role> roles = new HashSet<>();
	private String firstName;
	private String lastName;
	@Indexed(unique = true, sparse = true)
	private String mobile;
	private String avatarUrl;

	private Instant createdAt;
	private Instant updatedAt;

}
