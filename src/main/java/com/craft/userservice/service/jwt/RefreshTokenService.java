package com.craft.userservice.service.jwt;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.craft.userservice.configuration.JwtProperties;
import com.craft.userservice.service.jwt.model.RefreshToken;
import com.craft.userservice.service.jwt.repository.RefreshTokenRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
	private final RefreshTokenRepository repository;
	private final JwtProperties jwtProperties;

	public RefreshToken create(String userId) {
		// За бажанням: дозволити тільки 1 активний refresh на користувача
		// опціонально: одна активна сесія на юзера
		// repository.deleteByUserId(userId);

		RefreshToken token = RefreshToken.builder().userId(userId).token(UUID.randomUUID().toString())
				.expiryDate(Instant.now().plusMillis(jwtProperties.getRefreshTokenExpirationMs())).build();
		return repository.save(token);
	}

	public Optional<RefreshToken> findByToken(String token) {
		return repository.findByToken(token);
	}

	public RefreshToken requireValid(String token) {
		RefreshToken rt = findByToken(token).orElseThrow(() -> new RuntimeException("Invalid refresh token"));
		if (rt.getExpiryDate().isBefore(Instant.now())) {
			repository.delete(rt);
			throw new RuntimeException("Refresh token expired");
		}
		return rt;
	}

	// Ротація: перевіряємо старий, видаляємо його, створюємо новий для того ж
	// userId.
	public RefreshToken rotate(String oldTokenValue) {
		RefreshToken old = requireValid(oldTokenValue);

		String userId = old.getUserId();
		repository.delete(old); // старий більше не працює

		RefreshToken fresh = create(userId); // створюємо новий
		return fresh;
	}

//	public void revokeByToken(String tokenValue) {
//		repository.findByToken(tokenValue).ifPresent(repository::delete);
//	}
	public void revokeByToken(String token, String userId) {
		long deleted = repository.deleteByTokenAndUserId(token, userId);
		if (deleted == 0) {
			throw new RuntimeException("Refresh token not found for this user");
		}
	}

	// логаут на всіх пристроях
	public void revokeAllByUserId(String userId) {
		long deleted = repository.deleteByUserId(userId);
		if (deleted == 0) {
			throw new RuntimeException("No refresh tokens found for this user");
		}
	}

}
