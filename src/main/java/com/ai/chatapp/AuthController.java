package com.ai.chatapp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ai.chatapp.dto.UserDto;

@RestController
@RequestMapping("/auth")
public class AuthController {
  @Autowired
  UserRepository userRepository;

  Logger logger = LoggerFactory.getLogger(AuthController.class);

  @PostMapping(path = "/signup", consumes = MediaType.APPLICATION_JSON_VALUE)
  public Long signup(@RequestBody UserDto userDto) {
    User user = userRepository.findByUsername(userDto.username());

    if (user != null)
      return (long) -1;

    user = new User();

    user.setUsername(userDto.username());
    user.setPassword(bCryptPasswordEncoder().encode(userDto.password()));

    userRepository.save(user);

    return user.getId();
  }

  @PostMapping(path = "/login", consumes = MediaType.APPLICATION_JSON_VALUE)
  public Long login(@RequestBody UserDto userDto) {
    User user = userRepository.findByUsername(userDto.username());

    if (user == null)
      return (long) -1;

    if (!bCryptPasswordEncoder().matches(userDto.password(), user.getPassword()))
      return (long) -2;

    return user.getId();
  }

  @GetMapping("/test")
  public String test() {
    return "test";
  }

  @Bean
  public BCryptPasswordEncoder bCryptPasswordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
