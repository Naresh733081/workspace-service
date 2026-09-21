package com.example.workspace.auth;

import com.example.workspace.exception.ApiException;
import com.example.workspace.exception.ErrorCode;
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

    // Responsible for actually WRITING the SecurityContext somewhere it will
    // survive between requests. HttpSessionSecurityContextRepository is the
    // traditional implementation — it stores the context as an attribute on
    // the HttpSession. (There's also a "do nothing" NullSecurityContextRepository,
    // which is what a stateless JWT setup uses later — nothing to persist
    // because the token itself carries the proof each time.)
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

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
            throw new ApiException(ErrorCode.CONFLICT, "Email already registered: " + request.email());
        }
        String hash = passwordEncoder.encode(request.password());
        userRepository.save(new User(request.email(), hash));
        return ResponseEntity.status(201).body("User created successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@Valid @RequestBody LoginRequest request,
                                      HttpServletRequest httpRequest,
                                      HttpServletResponse httpResponse) {
        Authentication authRequest = new UsernamePasswordAuthenticationToken(request.email(), request.password());

        // throws BadCredentialsException on failure
        Authentication authResult = authenticationManager.authenticate(authRequest);

        // Up to this point, authResult only exists on the stack of this one
        // method call. SecurityContextHolder is what the REST of the app
        // (this request, and — once persisted below — future requests) reads
        // to find out "who is currently authenticated."
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authResult);
        SecurityContextHolder.setContext(context);

        // This is the step that actually makes it survive past this one
        // request. Without this line, the context above would be correct for
        // the duration of THIS request only, then vanish — same problem as
        // before, just moved one line later. This call is what triggers
        // session creation and writes SPRING_SECURITY_CONTEXT into it, which
        // is what causes the JSESSIONID cookie to appear on the response.
        securityContextRepository.saveContext(context, httpRequest, httpResponse);

        return ResponseEntity.ok().body("login successfully");
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