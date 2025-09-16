package com.craft.userservice.jwt.model;

import java.time.Instant;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Document(collection = "refresh_tokens")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {
	@Id
    private String id;
    private String userId;
    
    @Indexed(unique = true)
    private String token;
    
 // TTL: авто-видалення після закінчення терміну
    @Indexed(expireAfterSeconds = 0)
    private Instant expiryDate;

}
