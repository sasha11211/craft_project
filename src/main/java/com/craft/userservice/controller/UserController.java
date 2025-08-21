package com.craft.userservice.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.craft.userservice.dto.response.UserResponseDto;
import com.craft.userservice.model.User;
import com.craft.userservice.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {
	private final UserRepository userRepository;

    @GetMapping("/current")
    public ResponseEntity<?> getCurrentUser(Authentication authentication) {
        String email = (String) authentication.getPrincipal(); // email з JWT
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        UserResponseDto response = new UserResponseDto(
                user.getId(),
                user.getFirstName(),
                user.getLastName(),
                user.getEmail()
        );
        
        return ResponseEntity.ok(response);
    }


}
