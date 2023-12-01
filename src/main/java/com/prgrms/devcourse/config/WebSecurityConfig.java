package com.prgrms.devcourse.config;

import com.prgrms.devcourse.user.UserService;
import jakarta.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    private final UserService userService;

    AuthenticationManager authenticationManager;

    @Autowired
    public WebSecurityConfig(UserService userService) {
        this.userService = userService;
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        //정적 리소스에 대한 필터기능 해제
        return (web) -> web.ignoring()
            .requestMatchers(
                new AntPathRequestMatcher("/assets/**")
                ,new AntPathRequestMatcher("/h2-console/**")
            );
    }

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
        builder.userDetailsService(userService).passwordEncoder(passwordEncoder());
        authenticationManager = builder.build();

        //시큐리티 필터 기능
        http
            .authorizeHttpRequests((authorizeRequests) ->
                authorizeRequests
                    .requestMatchers(new AntPathRequestMatcher("/me")).hasAnyRole("USER", "ADMIN")
                    .anyRequest().permitAll()
            )

            .formLogin((formLogin) ->
                formLogin
                    .defaultSuccessUrl("/")
                    .permitAll()
            )
            .logout((logout) ->
                logout
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                    .logoutSuccessUrl("/")
                    //로그아웃 시 세션에서 정보 invalidate (생략 가능)
                    .invalidateHttpSession(true)
                    //로그아웃 시 SecurityContext를 초기화 (생략 가능)
                    .clearAuthentication(true)
            )
            .rememberMe((me) ->
                me.rememberMeParameter("remember-me")
                    .tokenValiditySeconds(300)
            )
            .authenticationManager(authenticationManager)
        //HTTP 요청을 HTTPS 요청으로 리다이렉트
//            .requiresChannel(channel ->
//                channel
//                    .anyRequest().requiresSecure()
//            )
        //Anonymous 필터 커스텀
//            .anonymous(anonymous ->
//                anonymous
//                    .principal("thisIsAnonymousUser")
//                    .authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN")
//            )
//            .exceptionHandling(handle ->
//                handle.accessDeniedHandler(accessDeniedHandler())
//            )
//            .httpBasic(Customizer.withDefaults());
        ;

        return http.build();
    }

    //로그인 가능한 사용자 계정 추가하기

    /**
     * InMemoryUserDetailsManager 객체를 사용한다면(보다 정확하게는 UserDetailsPasswordService 인터페이스 구현체) 최초 로그인 1회
     * 성공시, {noop} 타입에서 → {bcrypt} 타입으로 PasswordEncoder가 변경된다.
     */
//    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
        UserDetails user = User.builder()
            .username("user")
            //Spring Security 5에서부터 DelegatingPasswordEncoder 클래스가 기본 Encoder로 사용됨
            //패스워드 앞에 prefix를 추가함으로써, 해시 알고리즘별 PasswordEncoder 선택
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

//    @Bean
    UserDetailsService userDetailsService(DataSource dataSource){
        JdbcDaoImpl jdbcDao = new JdbcDaoImpl();
        jdbcDao.setDataSource(dataSource);
        return jdbcDao;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    //예외 핸들러 추가
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return ((request, response, accessDeniedException) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;

            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain");
            response.getWriter().write("## ACCESS DENIED ##");
            response.getWriter().flush();
            response.getWriter().close();
        });
    }
}
