package com.example.workspace.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

// Housekeeping only. Token validity is enforced by JWT expiry and the
// revoked flag at request time, so if this job is late, skipped, or the
// app was asleep at 3am, nothing breaks. The table is just bigger for a
// while. Never make a security decision depend on this having run.
//
// Known limits, accepted for now:
// - With more than one app instance, every instance runs this. The DELETE
//   is idempotent so it's harmless, only redundant. If that ever matters,
//   add ShedLock so only one instance runs each tick.
// - On a host that sleeps idle instances (some free tiers), the scheduled
//   time can pass while the app is down. It simply runs at the next
//   scheduled time it's awake for.
@Component
public class RefreshTokenCleanupJob {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenCleanupJob.class);
    private static final int BATCH_SIZE = 10000;

    private final RefreshTokenRepository refreshTokenRepository;
    private final Duration retention;

    public RefreshTokenCleanupJob(RefreshTokenRepository refreshTokenRepository,
                                  // ISO-8601 duration (P1D = 1 day), bound to java.time.Duration
                                  // by Spring. Value lives in application.properties.
                                  @Value("${app.cleanup.refresh-tokens.retention}") Duration retention) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.retention = retention;
    }

    @Scheduled(cron = "${app.cleanup.refresh-tokens.cron}")
    public void deleteExpiredTokens() {
        // only rows expired MORE than `retention` ago are removed. Rows that
        // expired recently, and rows still valid, are never touched.
        Instant cutoff = Instant.now().minus(retention);
        long total = 0;

        try {
            int deleted;
            do {
                // each batch is its own short transaction (see repository)
                deleted = refreshTokenRepository.deleteExpiredBatch(cutoff, BATCH_SIZE);
                total += deleted;
            } while (deleted == BATCH_SIZE);

            log.info("Refresh token cleanup finished: deleted={} cutoff={}", total, cutoff);
        } catch (Exception ex) {
            // swallow after logging so one failed run doesn't affect the
            // scheduler thread, the next tick simply tries again
            log.error("Refresh token cleanup failed after deleting {} rows", total, ex);
        }
    }
}