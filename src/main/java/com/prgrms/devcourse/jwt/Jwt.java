package com.prgrms.devcourse.jwt;

import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class Jwt {
    private final String issuer;
    private final String clientSecret;
    private final int expirySeconds;

    private final Algorithm algorithm;

    private final JWTVerifier jwtVerifier;

    public Jwt(String issuer, String client, int expirySeconds) {
        this.issuer = issuer;
        this.clientSecret = client;
        this.expirySeconds = expirySeconds;
        this.algorithm = Algorithm.HMAC512(clientSecret);
        this.jwtVerifier = com.auth0.jwt.JWT.require(algorithm)
            .withIssuer(issuer)
            .build();
    }

    //encoding
    public String sign(Claims claims){
        Date now = new Date();
        JWTCreator.Builder builder = com.auth0.jwt.JWT.create();
        builder.withIssuer(issuer);
        builder.withIssuedAt(now);
        if(expirySeconds>0){
            builder.withExpiresAt(new Date(now.getTime() + expirySeconds * 1_000L));
        }
        builder.withClaim("username", claims.username);
        builder.withArrayClaim("roles", claims.roles);
        return builder.sign(algorithm);
    }

    //decoding
    public Claims verify(String token){
        return new Claims(jwtVerifier.verify(token));
    }

    static public class Claims{
        String username;
        String[] roles;
        Date iat;
        Date exp;

        private Claims(){}

        Claims(DecodedJWT decodedJWT){
            Claim username = decodedJWT.getClaim("username");
            if(!username.isNull()){
                this.username = username.asString();
            }

            Claim roles = decodedJWT.getClaim("roles");
            if(!roles.isNull()){
                this.roles = roles.asArray(String.class);
            }

            this.iat = decodedJWT.getIssuedAt();
            this.exp = decodedJWT.getExpiresAt();
        }

        public static Claims from(String username, String[] roles){
            Claims claims = new Claims();
            claims.username = username;
            claims.roles = roles;
            return claims;
        }

        public Map<String, Object> asMap(){
            Map<String, Object> map = new HashMap<>();
            map.put("username", username);
            map.put("roles", roles);
            map.put("iat", iat());
            map.put("exp", exp);
            return map;
        }

        public long iat(){
            return iat != null ? iat.getTime(): -1;
        }

        public long exp(){
            return exp != null ? exp.getTime(): -1;
        }

        @Override
        public String toString() {
            return "Claims{" +
                "username='" + username + '\'' +
                ", roles=" + Arrays.toString(roles) +
                ", iat=" + iat +
                ", exp=" + exp +
                '}';
        }
    }

}
