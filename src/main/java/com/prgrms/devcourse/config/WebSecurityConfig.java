package com.prgrms.devcourse.config;

import jakarta.security.auth.message.config.AuthConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFilter;

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

    //로그인 가능한 사용자 계정 추가하기
    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager(){
        UserDetails user = User.builder()
            .username("user")
            //Spring Security 5에서부터 DelegatingPasswordEncoder 클래스가 기본 Encoder로 사용됨
            //{noop} -> 암호화 되지 않은 비밀번호
            .password("{noop}user123")
            .roles("USER")
            .build();
        UserDetails admin = User.builder()
            .username("admin")
            .password("{noop}admin123")
            .roles("ADMIN")
            .build();
        return new InMemoryUserDetailsManager(user, admin);
    }
}
