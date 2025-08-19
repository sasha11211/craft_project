package com.craft.userservice.service;

import java.time.LocalDateTime;
import java.util.Set;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.craft.userservice.dto.AuthResponse;
import com.craft.userservice.dto.LoginRequest;
import com.craft.userservice.dto.RefreshRequest;
import com.craft.userservice.dto.RegisterRequest;
import com.craft.userservice.model.RefreshToken;
import com.craft.userservice.model.User;
import com.craft.userservice.repository.UserRepository;
import com.craft.userservice.security.JwtUtil;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {
	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtUtil jwtUtil;
	private final RefreshTokenService refreshTokenService;

	public ResponseEntity<?> register(RegisterRequest request) {
		if (userRepository.existsByEmail(request.getEmail())) {
			throw new RuntimeException("Email already exists!");
		}
		User user = User.builder().firstName(request.getFirstName()).lastName(request.getLastName())
				.email(request.getEmail()).password(passwordEncoder.encode(request.getPassword())).roles(Set.of("USER"))
				.createdAt(LocalDateTime.now()).updatedAt(LocalDateTime.now()).build();
		userRepository.save(user);

		String access = jwtUtil.generateToken(user.getEmail());
		String refresh = refreshTokenService.create(user.getId()).getToken();
		return ResponseEntity.ok(new AuthResponse(access, refresh));
	}

	public ResponseEntity<?> login(LoginRequest request) {
		User user = userRepository.findByEmail(request.getEmail())
				.orElseThrow(() -> new RuntimeException("User not found"));
		if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
			throw new RuntimeException("Invalid password");
		}
		String access = jwtUtil.generateToken(user.getEmail());
		String refresh = refreshTokenService.create(user.getId()).getToken();
		return ResponseEntity.ok(new AuthResponse(access, refresh));
	}

	// ротація refresh + новий access
	public ResponseEntity<?> refreshToken(RefreshRequest request) {
		try {
			RefreshToken newRefresh = refreshTokenService.rotate(request.getRefreshToken());

			User user = userRepository.findById(newRefresh.getUserId())
					.orElseThrow(() -> new RuntimeException("User not found"));

			String newAccessToken = jwtUtil.generateToken(user.getEmail());
			return ResponseEntity.ok(new AuthResponse(newAccessToken, newRefresh.getToken()));

		} catch (Exception e) {
			return ResponseEntity.badRequest().body("Invalid or expired refresh token");
		}

	}

	public ResponseEntity<?> logout(RefreshRequest request, Authentication authentication) {
	    if (authentication == null || authentication.getPrincipal() == null) {
	        return ResponseEntity.status(401).body("Unauthorized");
	    }
	    String email = (String) authentication.getPrincipal();
	    User user = userRepository.findByEmail(email)
	            .orElseThrow(() -> new RuntimeException("User not found"));

	    refreshTokenService.revokeByToken(request.getRefreshToken(), user.getId());
	    return ResponseEntity.ok("Logged out from current device");
	}

	public ResponseEntity<?> logoutAll(Authentication authentication) {
	    if (authentication == null || authentication.getPrincipal() == null) {
	        return ResponseEntity.status(401).body("Unauthorized");
	    }
	    String email = (String) authentication.getPrincipal();
	    User user = userRepository.findByEmail(email)
	            .orElseThrow(() -> new RuntimeException("User not found"));

	    refreshTokenService.revokeAllByUserId(user.getId());
	    return ResponseEntity.ok("Logged out from all devices");
	}

}
