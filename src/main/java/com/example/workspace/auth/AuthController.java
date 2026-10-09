package com.example.workspace.auth;

import com.example.workspace.exception.ApiException;
import com.example.workspace.exception.ErrorCode;
import com.example.workspace.security.JwtService;
import com.example.workspace.user.RegisterRequest;
import com.example.workspace.user.User;
import com.example.workspace.user.UserDetailsImpl;
import com.example.workspace.user.UserRepository;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    // Responsible for actually WRITING the SecurityContext somewhere it will
    // survive between requests. HttpSessionSecurityContextRepository is the
    // traditional implementation — it stores the context as an attribute on
    // the HttpSession. (There's also a "do nothing" NullSecurityContextRepository,
    // which is what a stateless JWT setup uses later — nothing to persist
    // because the token itself carries the proof each time.)
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    public AuthController(UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          AuthenticationManager authenticationManager,
                          JwtService jwtService,
                          RefreshTokenRepository refreshTokenRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@Valid @RequestBody RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new ApiException(ErrorCode.CONFLICT, "Email already registered: " + request.email());
        }
        String hash = passwordEncoder.encode(request.password());
        userRepository.save(new User(request.email(), hash));
        return ResponseEntity.status(201).body("User created successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        Authentication authRequest = new UsernamePasswordAuthenticationToken(request.email(), request.password());

        Authentication authResult;
        try {
            authResult = authenticationManager.authenticate(authRequest);
        } catch (BadCredentialsException ex) {
            // Spring throws this for a wrong password AND for an unknown email
            // (it hides user-not-found on purpose), so both land here and the
            // client can't tell which one it was.
            log.warn("Login failed: email={}", request.email());
            throw new ApiException(ErrorCode.INVALID_CREDENTIALS);
        }

        // UserDetailsImpl already carries the id — DaoAuthenticationProvider
        // loaded it once during authenticate() above via
        // UserDetailsServiceImpl. No need to hit the database again for the
        // same row.
        UserDetailsImpl principal = (UserDetailsImpl) authResult.getPrincipal();

        LoginResponse tokens = issueTokenPair(principal.getUsername(), principal.getId());
        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        Claims claims = jwtService.extractClaimsForRefreshToken(request.refreshToken());
        String jti = claims.getId();
        String email = claims.getSubject();

        RefreshToken stored = refreshTokenRepository.findByJti(jti)
                .orElseThrow(() -> new ApiException(ErrorCode.INVALID_TOKEN));

        if (stored.isRevoked()) {
            throw new ApiException(ErrorCode.INVALID_TOKEN);
        }

        stored.revoke();
        refreshTokenRepository.save(stored);

        // refresh IS a case where we genuinely don't have the user id handy
        // (only the email, from the token claims) — one lookup here is
        // unavoidable and correct, unlike login where we already had it
        Long userId = stored.getUserId();
        return ResponseEntity.ok(issueTokenPair(email, userId));
    }

    private LoginResponse issueTokenPair(String email, Long userId) {
        String accessToken = jwtService.generateAccessToken(email);

        String jti = UUID.randomUUID().toString();
        JwtService.IssuedToken refresh = jwtService.generateRefreshTokenDetailed(email, jti);

        // expiresAt comes directly from the token we just built — same value
        // encoded in the JWT's own "exp" claim, not a separately hardcoded
        // duration that could drift out of sync with jwt.refresh-token-expiration-ms
        refreshTokenRepository.save(new RefreshToken(jti, userId, refresh.expiresAt()));

        return new LoginResponse(accessToken, refresh.token());
    }

    @GetMapping("/me")
    public ResponseEntity<String> me() {
        // By the time this method runs, Spring Security's own filter chain
        // has already read the session (via the cookie sent by the client)
        // and repopulated SecurityContextHolder for us — we didn't have to
        // do anything here to "look up the session." That restoration
        // happens BEFORE the controller is even invoked.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).build();
        }

        UserDetailsImpl principal = (UserDetailsImpl) authentication.getPrincipal();
        return ResponseEntity.ok("Authenticated as: " + principal.getUsername());
    }
}