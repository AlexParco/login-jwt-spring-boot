package com.jwtlogin.app.controllers;

import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.jwtlogin.app.models.User;
import com.jwtlogin.app.models.UserDetailsImpl;
import com.jwtlogin.app.models.payload.request.LoginRequest;
import com.jwtlogin.app.models.payload.response.Response;
import com.jwtlogin.app.models.payload.response.UserWithToken;
import com.jwtlogin.app.security.jwt.JwtUtils;
import com.jwtlogin.app.services.UserService;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtils jwtUtil;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User registerRequest) {
        try {
            if (userService.existsByUsername(registerRequest.getUsername())) {
                return ResponseEntity.badRequest().body(new Response<String>(
                        HttpServletResponse.SC_BAD_REQUEST,
                        "username is alredy taken",
                        null));
            }

            registerRequest.setPassword(encoder.encode(registerRequest.getPassword()));

            User userCreated = userService.save(registerRequest);
            return ResponseEntity.accepted().body(new Response<User>(
                    HttpServletResponse.SC_ACCEPTED,
                    "user registered successfully",
                    userCreated));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(new Response<String>(
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    e.getMessage(),
                    null));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            if (!userService.existsByUsername(loginRequest.getUsername())) {
                return ResponseEntity.badRequest().body(new Response<Object>(
                        HttpServletResponse.SC_BAD_REQUEST,
                        "user with this username not exists",
                        new Object()));
            }
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),
                            loginRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

            List<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());

            userDetails.setRole(roles.get(0));

            User user = userService.findByUsername(userDetails.getUsername()).orElseThrow();

            String token = jwtUtil.generateToken(userDetails.getUsername());
            return ResponseEntity.ok().body(new Response<UserWithToken>(
                    HttpServletResponse.SC_OK,
                    "",
                    new UserWithToken(user, token)));

        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(new Response<String>(
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    e.getMessage(),
                    null));
        }
    }

}
