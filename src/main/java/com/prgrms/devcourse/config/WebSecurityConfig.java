package com.prgrms.devcourse.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig{

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers("/asserts/**");
    }

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
            .authorizeHttpRequests((authorizeRequests) ->
                authorizeRequests
                    .requestMatchers("/me").hasAnyRole("USER", "ADMIN")
                    .anyRequest().permitAll()
            )

            .formLogin((formLogin) ->
                formLogin
                    .defaultSuccessUrl("/")
                    .permitAll()
            );

        return http.build();
    }
}
