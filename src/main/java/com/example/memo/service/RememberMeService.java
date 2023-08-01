package com.example.memo.service;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class RememberMeService extends TokenBasedRememberMeServices {
    public RememberMeService(UserDetailsService userDetailsService) {
        super(UUID.randomUUID().toString(), userDetailsService);
    }
}
