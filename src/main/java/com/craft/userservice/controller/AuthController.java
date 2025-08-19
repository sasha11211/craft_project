package com.craft.userservice.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.craft.userservice.dto.LoginRequest;
import com.craft.userservice.dto.RefreshRequest;
import com.craft.userservice.dto.RegisterRequest;
import com.craft.userservice.service.AuthService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
	private final AuthService authService;

	@PostMapping("/register")
	public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
		return authService.register(request);
	}

	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody LoginRequest request) {
		return authService.login(request);
	}

	@PostMapping("/refresh")
	public ResponseEntity<?> refresh(@RequestBody RefreshRequest request) {
		return authService.refreshToken(request);
	}

	@PostMapping("/logout")
	public ResponseEntity<?> logout(@RequestBody RefreshRequest request, Authentication authentication) {
	    return authService.logout(request, authentication);
	}
	
	@PostMapping("/logout-all")
	public ResponseEntity<?> logoutAll(Authentication authentication) {
	    return authService.logoutAll(authentication);
	}

}
