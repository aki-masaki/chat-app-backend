package com.ai.chatapp;

import java.io.IOException;
import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private AuthenticationManager authenticationManager;

  @Autowired
  private UserRepository userRepository;

  public JWTAuthenticationFilter() {
    this.authenticationManager = authentication -> authentication;

    setFilterProcessesUrl("/auth/login");
  }

  @Override
  @Autowired
  public void setAuthenticationManager(AuthenticationManager authenticationManager) {
    super.setAuthenticationManager(authenticationManager);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest req,
      HttpServletResponse res) throws AuthenticationException {
    try {
      User user = new ObjectMapper()
          .readValue(req.getInputStream(), User.class);

      User foundUser = userRepository.findByUsername(user.getUsername());

      if (foundUser == null)
        return null;

      // Incorrect password
      if (!new BCryptPasswordEncoder().matches(user.getPassword(), foundUser.getPassword()))
        return null;

      return authenticationManager.authenticate(
          new UsernamePasswordAuthenticationToken(
              user.getUsername(),
              user.getPassword()));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest req,
      HttpServletResponse res,
      FilterChain chain,
      Authentication auth) throws IOException {
    String token = JWT.create()
        .withSubject((String) auth.getPrincipal())
        .withExpiresAt(new Date(System.currentTimeMillis() + 1209600033)) // 2 weeks
        .sign(Algorithm.HMAC512(Constants.JWT_SECRET.getBytes()));

    res.addHeader(Constants.JWT_HEADER_NAME, token);
    res.getWriter().append("{\"token\": \"" + token + "\", \"username\": \"" + (String) auth.getPrincipal() + "\"}");
  }
}