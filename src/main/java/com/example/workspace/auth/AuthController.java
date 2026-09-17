package com.example.workspace.auth;

import com.example.workspace.user.RegisterRequest;
import com.example.workspace.user.User;
import com.example.workspace.user.UserRepository;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthController(UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@Valid @RequestBody RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalStateException("Email already registered: " + request.email());
        }
        String hash = passwordEncoder.encode(request.password());
        userRepository.save(new User(request.email(), hash));
        return ResponseEntity.status(201).body("User created successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<Void> login(@Valid @RequestBody LoginRequest request) {
        // "unauthenticated" token — this is the (principal, credentials) form,
        // meaning "here's what was submitted, please verify it."
        Authentication authRequest = new UsernamePasswordAuthenticationToken(request.email(), request.password());

        // This line does the real work. AuthenticationManager delegates to
        // DaoAuthenticationProvider, which calls UserDetailsServiceImpl to
        // load the user, then PasswordEncoder to check the password.
        // Throws BadCredentialsException if the user doesn't exist OR the
        // password is wrong — deliberately the same exception for both, so
        // we don't leak which one it was.
        authenticationManager.authenticate(authRequest);

        return ResponseEntity.ok().build();
    }
}