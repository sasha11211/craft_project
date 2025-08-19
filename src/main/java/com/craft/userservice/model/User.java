package com.craft.userservice.model;

import java.time.LocalDateTime;
import java.util.Set;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Document(collection = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
	@Id
	private String id;
	
	private String firstName;
    private String lastName;
    private String email;
    private String password;
    private Set<String> roles;
    
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

}
