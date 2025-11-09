package com.craft.userservice.user;

import java.time.Instant;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;

import org.modelmapper.ModelMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.craft.userservice.configuration.JwtProperties;
import com.craft.userservice.configuration.enums.Role;
import com.craft.userservice.jwt.RefreshTokenService;
import com.craft.userservice.jwt.model.RefreshToken;
import com.craft.userservice.security.JwtUtil;
import com.craft.userservice.user.dto.AddRoleDto;
import com.craft.userservice.user.dto.LoginRequestDto;
import com.craft.userservice.user.dto.RegisterRequestDto;
import com.craft.userservice.user.dto.UpdateUserDto;
import com.craft.userservice.user.dto.exceptions.UserNotFoundException;
import com.craft.userservice.user.dto.exceptions.UserNotFoundExceptionById;
import com.craft.userservice.user.dto.response.UpdateUserResponseDto;
import com.craft.userservice.user.dto.response.UserResponseDto;
import com.craft.userservice.user.model.Address;
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
	private final JwtProperties jwtProperties;

	// ===== cookie helpers =====
	private ResponseCookie buildCookie(String name, String value, long maxAgeSeconds, String path) {
		return ResponseCookie
				.from(name, value)
				.httpOnly(true)
				.secure(true)
				.sameSite("None")
				.path(path)
				.maxAge(maxAgeSeconds)
				.build();
	}

	private ResponseCookie clearCookie(String name, String path) {
		return ResponseCookie
				.from(name, "")
				.httpOnly(true)
				.secure(true)
				.sameSite("None")
				.path(path)
				.maxAge(0)
				.build();
	}

	@Override
	public ResponseEntity<?> register(RegisterRequestDto registerRequestDto) {
		String email = registerRequestDto.getEmail().toLowerCase();
		if (userRepository.existsByEmail(email)) {
			return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already in use");
		}
		User user = User.builder()
				.email(email)
				.password(passwordEncoder.encode(registerRequestDto.getPassword()))
				.roles(new HashSet<>(Set.of(Role.ROLE_CUSTOMER)))
				.createdAt(Instant.now())
				.updatedAt(Instant.now())
				.build();
		if (registerRequestDto.getFirstName() != null && !registerRequestDto.getFirstName().isBlank()) {
			user.setFirstName(registerRequestDto.getFirstName());
		}
		if (registerRequestDto.getLastName() != null && !registerRequestDto.getLastName().isBlank()) {
			user.setLastName(registerRequestDto.getLastName());
		}
		if (registerRequestDto.isRegisterAsSeller()) {
			user.getRoles().add(Role.ROLE_SELLER);
		} 

		userRepository.save(user);
		UserResponseDto userResponseDto = modelMapper.map(user, UserResponseDto.class);

		String access = jwtUtil.generateToken(user.getEmail());
		String refresh = refreshTokenService.create(user.getId()).getToken();

		long accessAge = jwtProperties.getAccessTokenExpirationMs() / 1000;
		long refreshAge = jwtProperties.getRefreshTokenExpirationMs() / 1000;

		ResponseCookie accessC = buildCookie("access_token", access, accessAge, "/");
		ResponseCookie refreshC = buildCookie("refresh_token", refresh, refreshAge, "/");

		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, accessC.toString())
				.header(HttpHeaders.SET_COOKIE, refreshC.toString()).body(userResponseDto);
	}

	@Override
	public ResponseEntity<?> login(LoginRequestDto loginRequestDto) {
		User user = userRepository.findByEmail(loginRequestDto.getEmail()).orElse(null);
		if (user == null || !passwordEncoder.matches(loginRequestDto.getPassword(), user.getPassword())) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid email or password");
		}

		UserResponseDto userResponseDto = modelMapper.map(user, UserResponseDto.class);

		String access = jwtUtil.generateToken(user.getEmail());
		String refresh = refreshTokenService.create(user.getId()).getToken();

		long accessAge = jwtProperties.getAccessTokenExpirationMs() / 1000;
		long refreshAge = jwtProperties.getRefreshTokenExpirationMs() / 1000;

		ResponseCookie accessC = buildCookie("access_token", access, accessAge, "/");
//		ResponseCookie refreshC = buildCookie("refresh_token", refresh, refreshAge, "/api/user/auth");
		ResponseCookie refreshC = buildCookie("refresh_token", refresh, refreshAge, "/");

		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, accessC.toString())
				.header(HttpHeaders.SET_COOKIE, refreshC.toString()).body(userResponseDto);

	}

	// ротація refresh + новий access
	@Override
	public ResponseEntity<?> refreshToken(String oldRefresh) {
		try {
			if (oldRefresh == null || oldRefresh.isBlank()) {
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Refresh token is required");
			}

			RefreshToken newRefresh = refreshTokenService.rotate(oldRefresh);

			User user = userRepository.findById(newRefresh.getUserId())
					.orElseThrow(() -> new UserNotFoundExceptionById(newRefresh.getUserId()));

			String newAccessToken = jwtUtil.generateToken(user.getEmail());
			long accessAge = jwtProperties.getAccessTokenExpirationMs() / 1000;
			long refreshAge = jwtProperties.getRefreshTokenExpirationMs() / 1000;
			ResponseCookie accessC = buildCookie("access_token", newAccessToken, accessAge, "/");
			ResponseCookie refreshC = buildCookie("refresh_token", newRefresh.getToken(), refreshAge, "/");
			return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, accessC.toString())
					.header(HttpHeaders.SET_COOKIE, refreshC.toString()).body("Token refreshed");

		} catch (UserNotFoundExceptionById e) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal server error");
		}

	}

	@Override
	public ResponseEntity<?> logout(String refreshToken, Authentication authentication) {
		if (authentication == null || authentication.getPrincipal() == null) {
			return ResponseEntity.status(401).body("Unauthorized");
		}
		String email = (String) authentication.getPrincipal();
		User user = userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));

		if (refreshToken == null || refreshToken.isBlank()) {
			return ResponseEntity.badRequest().body("Refresh token missing");
		}

		refreshTokenService.revokeByToken(refreshToken, user.getId());
		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, clearCookie("access_token", "/").toString())
				.header(HttpHeaders.SET_COOKIE, clearCookie("refresh_token", "/").toString())
				.body("Logged out from current device");
	}

	@Override
	public ResponseEntity<?> logoutAll(Authentication authentication) {
		if (authentication == null || authentication.getPrincipal() == null) {
			return ResponseEntity.status(401).body("Unauthorized");
		}
		String email = (String) authentication.getPrincipal();
		User user = userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));

		refreshTokenService.revokeAllByUserId(user.getId());

		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, clearCookie("access_token", "/").toString())
				.header(HttpHeaders.SET_COOKIE, clearCookie("refresh_token", "/").toString())
				.body("Logged out from all devices");
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
				userRepository.findByMobile(updateUserDto.getMobile())
						.filter(other -> !other.getId().equals(user.getId())).ifPresent(other -> {
							throw new IllegalArgumentException("Mobile already in use");
						});
			}
			// перевірка унікальності логіна
			if (updateUserDto.getUserName() != null && !updateUserDto.getUserName().isBlank()) {
				userRepository.findByUserName(updateUserDto.getUserName())
						.filter(other -> !other.getId().equals(user.getId())).ifPresent(other -> {
							throw new IllegalArgumentException("User name already in use");
						});
				user.setUserName(updateUserDto.getUserName());
			}
			// адреса
			if (updateUserDto.getAddress() != null) {
				Address address = modelMapper.map(updateUserDto.getAddress(), Address.class);
				user.setAddress(address);
			}

			modelMapper.map(updateUserDto, user);
			user.setUpdatedAt(Instant.now());
			userRepository.save(user);

			UpdateUserResponseDto updateUserResponseDto = modelMapper.map(user, UpdateUserResponseDto.class);
			return ResponseEntity.ok(updateUserResponseDto);
		} catch (UserNotFoundException e) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
		} catch (IllegalArgumentException e) {
			return ResponseEntity.status(HttpStatus.CONFLICT).body(e.getMessage());
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal server error");
		}

	}

	@Override
	public ResponseEntity<?> addRole(AddRoleDto addRoleDto, Authentication authentication) {
		try {
			if (authentication == null || authentication.getPrincipal() == null) {
				return ResponseEntity.status(401).body("Unauthorized");
			}
			Role role = Role.valueOf(addRoleDto.getRole());
			// не дозволяємо самостійно призначати не-whitelisted ролі
			if (role == null || !EnumSet.of(Role.ROLE_SELLER).contains(role)) {
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body("This role cannot be self-assigned");
			}
			String email = (String) authentication.getPrincipal();
			User user = userRepository.findByEmail(email).orElseThrow(() -> new UserNotFoundException(email));

			if (user.getRoles() != null && user.getRoles().contains(role)) {
				UpdateUserResponseDto updateUserResponseDto = modelMapper.map(user, UpdateUserResponseDto.class);
				return ResponseEntity.ok(updateUserResponseDto);
			}
			user.getRoles().add(role);
			user.setUpdatedAt(Instant.now());
			userRepository.save(user);
			UpdateUserResponseDto updateUserResponseDto = modelMapper.map(user, UpdateUserResponseDto.class);
			return ResponseEntity.ok(updateUserResponseDto);
		} catch (UserNotFoundException e) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
		} catch (IllegalArgumentException | NullPointerException e) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid role value");
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal server error");
		}
	}

}
