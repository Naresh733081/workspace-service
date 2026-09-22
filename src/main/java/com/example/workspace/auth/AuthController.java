package com.example.workspace.auth;

import com.example.workspace.exception.ApiException;
import com.example.workspace.exception.ErrorCode;
import com.example.workspace.security.JwtService;
import com.example.workspace.user.RegisterRequest;
import com.example.workspace.user.User;
import com.example.workspace.user.UserDetailsImpl;
import com.example.workspace.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

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
                          JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
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
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request,
                                      HttpServletRequest httpRequest,
                                      HttpServletResponse httpResponse) {
        Authentication authRequest = new UsernamePasswordAuthenticationToken(request.email(), request.password());

        // throws BadCredentialsException on failure
        Authentication authResult = authenticationManager.authenticate(authRequest);

        // issue a token. Nothing consumes this yet — we're proving
        // generation works before building anything that reads it back.
        String accessToken = jwtService.generateToken(authResult.getName());

        return ResponseEntity.ok(new LoginResponse(accessToken));
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