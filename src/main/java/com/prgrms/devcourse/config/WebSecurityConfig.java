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
        //정적 리소스에 대한 필터기능 해제
        return (web) -> web.ignoring().requestMatchers("/assets/**");
    }

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        //시큐리티 필터 기능
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
