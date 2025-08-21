package com.craft.userservice.service;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.craft.userservice.dto.LoginRequestDto;
import com.craft.userservice.dto.RefreshRequestDto;
import com.craft.userservice.dto.RegisterRequestDto;
import com.craft.userservice.dto.response.AuthResponseDto;
import com.craft.userservice.dto.response.CustomerResponseDto;
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
	private final ModelMapper modelMapper;

	public ResponseEntity<?> register(RegisterRequestDto request) {
		if (userRepository.existsByEmail(request.getEmail())) {
			return ResponseEntity.badRequest().body("Email already in use");
		}
		User user = User.builder().email(request.getEmail()).password(passwordEncoder.encode(request.getPassword()))
				.roles(new HashSet<>(Set.of(Role.ROLE_CUSTOMER))).createdAt(Instant.now()).updatedAt(Instant.now())
				.build();
		userRepository.save(user);
		String accessToken = jwtUtil.generateToken(user.getEmail());
		String refreshToken = refreshTokenService.create(user.getId()).getToken();
		CustomerResponseDto customerResponseDto = modelMapper.map(user, CustomerResponseDto.class);
		customerResponseDto.setAccessToken(accessToken);
		customerResponseDto.setRefreshToken(refreshToken);
		return ResponseEntity.ok(customerResponseDto);
	}

	public ResponseEntity<?> login(LoginRequestDto request) {
		User user = userRepository.findByEmail(request.getEmail()).orElse(null);
		if (user == null || !passwordEncoder.matches(request.getPassword(), user.getPassword())) {
			return ResponseEntity.badRequest().body("Invalid email or password");
		}

		String accessToken = jwtUtil.generateToken(user.getEmail());
		String refreshToken = refreshTokenService.create(user.getId()).getToken();

		CustomerResponseDto customerResponseDto = modelMapper.map(user, CustomerResponseDto.class);
		customerResponseDto.setAccessToken(accessToken);
		customerResponseDto.setRefreshToken(refreshToken);
		return ResponseEntity.ok(customerResponseDto);

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
		User user = userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));

		refreshTokenService.revokeByToken(request.getRefreshToken(), user.getId());
		return ResponseEntity.ok("Logged out from current device");
	}

	public ResponseEntity<?> logoutAll(Authentication authentication) {
		if (authentication == null || authentication.getPrincipal() == null) {
			return ResponseEntity.status(401).body("Unauthorized");
		}
		String email = (String) authentication.getPrincipal();
		User user = userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));

		refreshTokenService.revokeAllByUserId(user.getId());
		return ResponseEntity.ok("Logged out from all devices");
	}

}
