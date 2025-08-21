package com.craft.userservice.service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.craft.userservice.dto.LoginRequestDto;
import com.craft.userservice.dto.RefreshRequestDto;
import com.craft.userservice.dto.RegisterRequestDto;
import com.craft.userservice.dto.response.AuthResponseDto;
import com.craft.userservice.enums.Role;
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

	public ResponseEntity<?> register(RegisterRequestDto request) {
		if (userRepository.existsByEmail(request.getEmail())) {
            return ResponseEntity.badRequest().body("Email already in use");
        }
		User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRoles(new HashSet<>(Set.of(Role.ROLE_CUSTOMER)));
        user.setCreatedAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);

		String access = jwtUtil.generateToken(user.getEmail());
		String refresh = refreshTokenService.create(user.getId()).getToken();
		return ResponseEntity.ok(new AuthResponseDto(access, refresh));
	}

	public ResponseEntity<?> login(LoginRequestDto request) {
		User user = userRepository.findByEmail(request.getEmail())
				.orElseThrow(() -> new RuntimeException("User not found"));
		if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
			throw new RuntimeException("Invalid password");
		}
		String access = jwtUtil.generateToken(user.getEmail());
		String refresh = refreshTokenService.create(user.getId()).getToken();
		return ResponseEntity.ok(new AuthResponseDto(access, refresh));
	}

	// ротація refresh + новий access
	public ResponseEntity<?> refreshToken(RefreshRequestDto request) {
		try {
			RefreshToken newRefresh = refreshTokenService.rotate(request.getRefreshToken());

			User user = userRepository.findById(newRefresh.getUserId())
					.orElseThrow(() -> new RuntimeException("User not found"));

			String newAccessToken = jwtUtil.generateToken(user.getEmail());
			return ResponseEntity.ok(new AuthResponseDto(newAccessToken, newRefresh.getToken()));

		} catch (Exception e) {
			return ResponseEntity.badRequest().body("Invalid or expired refresh token");
		}

	}

	public ResponseEntity<?> logout(RefreshRequestDto request, Authentication authentication) {
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
