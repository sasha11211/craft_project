package com.craft.userservice.user;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.craft.userservice.service.jwt.dto.RefreshRequestDto;
import com.craft.userservice.user.dto.LoginRequestDto;
import com.craft.userservice.user.dto.RegisterRequestDto;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class UserController {
	private final AuthService authService;

	@PostMapping("/register")
	public ResponseEntity<?> register(@RequestBody RegisterRequestDto request) {
		return authService.register(request);
	}

	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody LoginRequestDto request) {
		return authService.login(request);
	}

	@PostMapping("/refresh")
	public ResponseEntity<?> refresh(@RequestBody RefreshRequestDto request) {
		return authService.refreshToken(request);
	}

	@PostMapping("/logout")
	public ResponseEntity<?> logout(@RequestBody RefreshRequestDto request, Authentication authentication) {
	    return authService.logout(request, authentication);
	}
	
	@PostMapping("/logout-all")
	public ResponseEntity<?> logoutAll(Authentication authentication) {
	    return authService.logoutAll(authentication);
	}

}
