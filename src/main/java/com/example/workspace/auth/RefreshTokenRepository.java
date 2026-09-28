package com.example.workspace.auth;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    @Query(value = "SELECT * FROM refresh_tokens WHERE jti = :jti", nativeQuery = true)
    Optional<RefreshToken> findByJti(@Param("jti") String jti);

    @Modifying
    @Query(value = "UPDATE refresh_tokens SET revoked = TRUE WHERE jti = :jti", nativeQuery = true)
    void revokeByJti(@Param("jti") String jti);

    @Transactional
    @Modifying
    @Query(value = """
        DELETE FROM refresh_tokens
        WHERE id IN (
            SELECT id FROM refresh_tokens
            WHERE expires_at < :cutoff
            LIMIT :batchSize
        )
        """, nativeQuery = true)
    int deleteExpiredBatch(@Param("cutoff") Instant cutoff, @Param("batchSize") int batchSize);
}