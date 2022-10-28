package com.jwtlogin.app.models.payload.response;

import com.jwtlogin.app.models.User;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserWithToken {
    private User user;
    private String token;

    public UserWithToken(User user, String token) {
        this.user = user;
        this.token = token;
    }
}
