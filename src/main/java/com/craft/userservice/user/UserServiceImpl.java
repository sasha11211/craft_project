package com.craft.userservice.user;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.craft.userservice.configuration.enums.Role;
import com.craft.userservice.jwt.RefreshTokenService;
import com.craft.userservice.jwt.dto.RefreshRequestDto;
import com.craft.userservice.jwt.model.RefreshToken;
import com.craft.userservice.security.JwtUtil;
import com.craft.userservice.user.dto.LoginRequestDto;
import com.craft.userservice.user.dto.RegisterRequestDto;
import com.craft.userservice.user.dto.UpdateUserDto;
import com.craft.userservice.user.dto.exceptions.UserNotFoundException;
import com.craft.userservice.user.dto.exceptions.UserNotFoundExceptionById;
import com.craft.userservice.user.dto.response.AuthResponseDto;
import com.craft.userservice.user.dto.response.UpdateUserResponseDto;
import com.craft.userservice.user.dto.response.UserResponseDto;
import com.craft.userservice.user.model.User;
import com.craft.userservice.user.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtUtil jwtUtil;
	private final RefreshTokenService refreshTokenService;
	private final ModelMapper modelMapper;

	@Override
	public ResponseEntity<?> register(RegisterRequestDto registerRequestDto) {
		String email = registerRequestDto.getEmail().toLowerCase();
		if (userRepository.existsByEmail(email)) {
			return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already in use");
		}
		User user = User.builder().email(email).password(passwordEncoder.encode(registerRequestDto.getPassword()))
				.roles(new HashSet<>(Set.of(Role.ROLE_CUSTOMER))).createdAt(Instant.now()).updatedAt(Instant.now())
				.build();
		userRepository.save(user);
		UserResponseDto userResponseDto = modelMapper.map(user, UserResponseDto.class);
		userResponseDto.setAccessToken(jwtUtil.generateToken(user.getEmail()));
		userResponseDto.setRefreshToken(refreshTokenService.create(user.getId()).getToken());
		return ResponseEntity.ok(userResponseDto);
	}

	@Override
	public ResponseEntity<?> login(LoginRequestDto loginRequestDto) {
		User user = userRepository.findByEmail(loginRequestDto.getEmail()).orElse(null);
		if (user == null || !passwordEncoder.matches(loginRequestDto.getPassword(), user.getPassword())) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid email or password");
		}
		UserResponseDto userResponseDto = modelMapper.map(user, UserResponseDto.class);
		userResponseDto.setAccessToken(jwtUtil.generateToken(user.getEmail()));
		userResponseDto.setRefreshToken(refreshTokenService.create(user.getId()).getToken());
		return ResponseEntity.ok(userResponseDto);

	}

	// ротація refresh + новий access
	@Override
	public ResponseEntity<?> refreshToken(RefreshRequestDto refreshRequestDto) {
		try {

			RefreshToken newRefresh = refreshTokenService.rotate(refreshRequestDto.getRefreshToken());

			User user = userRepository.findById(newRefresh.getUserId())
					.orElseThrow(() -> new UserNotFoundExceptionById(newRefresh.getUserId()));

			String newAccessToken = jwtUtil.generateToken(user.getEmail());
			return ResponseEntity.ok(new AuthResponseDto(newAccessToken, newRefresh.getToken()));

		} catch (UserNotFoundExceptionById e) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal server error");
		}

	}

	@Override
	public ResponseEntity<?> logout(RefreshRequestDto refreshRequestDto, Authentication authentication) {
		if (authentication == null || authentication.getPrincipal() == null) {
			return ResponseEntity.status(401).body("Unauthorized");
		}
		String email = (String) authentication.getPrincipal();
		User user = userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));

		refreshTokenService.revokeByToken(refreshRequestDto.getRefreshToken(), user.getId());
		return ResponseEntity.ok("Logged out from current device");
	}

	@Override
	public ResponseEntity<?> logoutAll(Authentication authentication) {
		if (authentication == null || authentication.getPrincipal() == null) {
			return ResponseEntity.status(401).body("Unauthorized");
		}
		String email = (String) authentication.getPrincipal();
		User user = userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));

		refreshTokenService.revokeAllByUserId(user.getId());
		return ResponseEntity.ok("Logged out from all devices");
	}

	@Override
	public ResponseEntity<?> getCurrentUser(Authentication authentication) {
		try {
			if (authentication == null || authentication.getPrincipal() == null) {
				return ResponseEntity.status(401).body("Unauthorized");
			}
			String email = (String) authentication.getPrincipal();
			User user = userRepository.findByEmail(email).orElseThrow(() -> new UserNotFoundException(email));
			UpdateUserResponseDto updateUserResponseDto = modelMapper.map(user, UpdateUserResponseDto.class);
			return ResponseEntity.ok(updateUserResponseDto);
		} catch (UserNotFoundException e) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal server error");
		}
		
	}

	@Override
	public ResponseEntity<?> updateUser(UpdateUserDto updateUserDto, Authentication authentication) {
		try {
			if (authentication == null || authentication.getPrincipal() == null) {
				return ResponseEntity.status(401).body("Unauthorized");
			}
			String email = (String) authentication.getPrincipal();
			User user = userRepository.findByEmail(email).orElseThrow(() -> new UserNotFoundException(email));
			// Перевірка, що мобільний не зайнятий іншим користувачем
			if (updateUserDto.getMobile() != null && !updateUserDto.getMobile().isBlank()) {
				userRepository.findByMobile(updateUserDto.getMobile()).filter(other -> !other.getId().equals(user.getId()))
						.ifPresent(other -> {
							throw new IllegalArgumentException("Mobile already in use");
						});
			}
			modelMapper.map(updateUserDto, user);
			user.setUpdatedAt(Instant.now());
			userRepository.save(user);

			UpdateUserResponseDto updateUserResponseDto  = modelMapper.map(user, UpdateUserResponseDto.class);
			return ResponseEntity.ok(updateUserResponseDto);
		} catch (UserNotFoundException e) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
		} catch (IllegalArgumentException e) {
			return ResponseEntity.status(HttpStatus.CONFLICT).body(e.getMessage());
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal server error");
		}
		
	}

}
