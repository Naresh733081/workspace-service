package com.example.workspace.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

// Spring Security doesn't know about our User entity — it only understands
// its own UserDetails interface. This class adapts our User to that
// contract so the rest of Spring Security's machinery (AuthenticationProvider,
// SecurityContext, etc.) can work with it without our entity needing to
// implement Security's interface directly.
public class UserDetailsImpl implements UserDetails {

    private final User user;

    public UserDetailsImpl(User user) {
        this.user = user;
    }

    // lets controllers get back our actual domain id later without
    // re-querying the database
    public Long getId() {
        return user.getId();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Spring Security's convention is authorities prefixed with "ROLE_"
        // when used with hasRole(...) later — we store just "USER"/"ADMIN"
        // in the database and add the prefix here.
        return List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole()));
    }

    @Override
    public String getPassword() {
        return user.getPasswordHash();
    }

    @Override
    public String getUsername() {
        // we don't have a separate username field — email is the identifier
        return user.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }
}