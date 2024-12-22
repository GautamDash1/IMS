package com.example.IMS.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    // Bean for password encryption using BCrypt
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Custom security filter chain to enable login, logout, and session handling
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable()) // Disable CSRF for simplicity
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/register", "/css/**", "/js/**", "/images/**").permitAll() // Public endpoints
                .requestMatchers("/admin/**").hasRole("ADMIN") // Admin-specific pages
                .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN") // User and admin access
                .anyRequest().authenticated() // All other requests require authentication
            )
            .formLogin(form -> form
                .loginPage("/login") // Custom login page URL
                .loginProcessingUrl("/perform_login") // URL for form submission
                .defaultSuccessUrl("/dashboard", true) // Redirect to dashboard after successful login
                .failureUrl("/login?error=true") // Redirect to login page on failure
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout") // Endpoint for logout
                .logoutSuccessUrl("/login?logout=true") // Redirect to login page after logout
                .invalidateHttpSession(true) // Invalidate session
                .deleteCookies("JSESSIONID") // Clear session cookies
                .permitAll()
            )
            .sessionManagement(session -> session
                .maximumSessions(1) // Only allow one session per user
                .expiredUrl("/login?expired=true") // Redirect when session expires
            );
        return http.build();
    }

    // Configure authentication manager (e.g., in-memory, JDBC, or custom user service)
    @Bean
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        // Example in-memory authentication
        auth.inMemoryAuthentication()
            .withUser("admin").password(passwordEncoder().encode("admin123")).roles("ADMIN")
            .and()
            .withUser("user").password(passwordEncoder().encode("user123")).roles("USER");

        // Uncomment and modify the following lines for custom UserDetailsService
        // auth.userDetailsService(customUserDetailsService).passwordEncoder(passwordEncoder());
    }
}
