package com.example.workspace.admin;

import com.example.workspace.user.User;
import com.example.workspace.user.UserRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final UserRepository userRepository;

    public AdminController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // No role check here — SecurityFilterChain already guarantees only
    // ROLE_ADMIN reaches this point (see SecurityConfig). This controller
    // doesn't need to know or care about roles at all.
    @GetMapping("/users")
    public List<Map<String, Object>> listUsers() {
        return userRepository.findAllUsers().stream()
                // building the map by hand, field by field, rather than
                // returning User directly — the point isn't the shape of
                // the response, it's that passwordHash must never leave
                // this method, DTO or no DTO
                .map(this::toResponse)
                .toList();
    }

    private Map<String, Object> toResponse(User user) {
        return Map.of(
                "id", user.getId(),
                "email", user.getEmail(),
                "role", user.getRole()
        );
    }
}