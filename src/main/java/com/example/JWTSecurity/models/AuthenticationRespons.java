package com.example.JWTSecurity.models;

public class AuthenticationRespons {
    private  final  String jwt;

    public AuthenticationRespons(String jwt) {
        this.jwt = jwt;
    }

    public String getJwt() {
        return jwt;
    }
}
