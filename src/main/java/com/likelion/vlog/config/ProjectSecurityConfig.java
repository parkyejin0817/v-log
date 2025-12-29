package com.likelion.vlog.config;

import com.likelion.vlog.exception.AuthEntryPoint;
import com.likelion.vlog.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@RequiredArgsConstructor
public class ProjectSecurityConfig {


    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf(csrf -> csrf.disable())

                .authorizeHttpRequests(auth -> auth

                        /* ==================================================
                           [1] 인증(Auth) - 인증 불필요
                        ================================================== */
                        .requestMatchers(HttpMethod.POST,
                                "/auth/signup",     // 회원가입
                                "/auth/login"       // 로그인
                        ).permitAll()


                        /* ==================================================
                           [2] 사용자(User) - 공개 조회
                        ================================================== */
                        .requestMatchers(HttpMethod.GET,
                                "/users/*"          // 사용자 프로필 조회
                        ).permitAll()


                        /* ==================================================
                           [3] 게시글(Post) - 공개 조회
                        ================================================== */
                        .requestMatchers(HttpMethod.GET,
                                "/api/v1/posts",           // 전체 게시글 조회
                                "/api/v1/posts/*"          // 게시글 상세 조회 (댓글 포함)
                        ).permitAll()


                        /* ==================================================
                           [4] 태그(Tag) - 공개 조회
                        ================================================== */
                        .requestMatchers(HttpMethod.GET,
                                "/tags/*"           // 태그 이름으로 조회
                        ).permitAll()


                        /* ==================================================
                           [5] 인증(Auth) - 로그인 필요
                        ================================================== */
                        .requestMatchers(HttpMethod.POST,
                                "/auth/logout"      // 로그아웃
                        ).authenticated()


                        /* ==================================================
                           [6] 사용자(User) - 본인 인증 필요
                        ================================================== */
                        .requestMatchers(HttpMethod.PUT,
                                "/users/*"          // 사용자 정보 수정
                        ).authenticated()

                        .requestMatchers(HttpMethod.DELETE,
                                "/users/*"          // 회원 탈퇴
                        ).authenticated()


                        /* ==================================================
                           [7] 팔로우(Follow) - 로그인 필요
                        ================================================== */
                        .requestMatchers(HttpMethod.POST,
                                "/users/*/follow"   // 팔로우
                        ).authenticated()

                        .requestMatchers(HttpMethod.DELETE,
                                "/users/*/follow"   // 언팔로우
                        ).authenticated()

                        .requestMatchers(HttpMethod.GET,
                                "/users/*/followers",   // 팔로워 목록
                                "/users/*/followings"   // 팔로잉 목록
                        ).authenticated()


                        /* ==================================================
                           [8] 게시글(Post) - 작성자 인증 필요
                        ================================================== */
                        .requestMatchers(HttpMethod.POST,
                                "/api/v1/posts"            // 게시글 작성
                        ).authenticated()

                        .requestMatchers(HttpMethod.PUT,
                                "/api/v1/posts/*"          // 게시글 수정
                        ).authenticated()

                        .requestMatchers(HttpMethod.DELETE,
                                "/api/v1/posts/*"          // 게시글 삭제
                        ).authenticated()


                        /* ==================================================
                           [9] 댓글(Comment) - 작성자 인증 필요
                        ================================================== */
                        .requestMatchers(HttpMethod.POST,
                                "/posts/*/comments" // 댓글 작성
                        ).authenticated()

                        .requestMatchers(HttpMethod.PUT,
                                "/posts/*/comments/*" // 댓글 수정
                        ).authenticated()

                        .requestMatchers(HttpMethod.DELETE,
                                "/posts/*/comments/*" // 댓글 삭제
                        ).authenticated()


                        /* ==================================================
                           [10] 답글(Reply) - 작성자 인증 필요
                        ================================================== */
                        .requestMatchers(HttpMethod.POST,
                                "/posts/*/comments/*/replies" // 답글 생성
                        ).authenticated()

                        .requestMatchers(HttpMethod.PUT,
                                "/posts/*/comments/*/replies/*" // 답글 수정
                        ).authenticated()

                        .requestMatchers(HttpMethod.DELETE,
                                "/posts/*/comments/*/replies/*" // 답글 삭제
                        ).authenticated()


                        /* ==================================================
                           [11] 좋아요(Like) - 로그인 필요
                        ================================================== */
                        .requestMatchers(HttpMethod.POST,
                                "/api/v1/posts/*/like"     // 좋아요
                        ).authenticated()

                        .requestMatchers(HttpMethod.DELETE,
                                "/api/v1/posts/*/like"     // 좋아요 취소
                        ).authenticated()

                        .requestMatchers(HttpMethod.GET,
                                "/api/v1/posts/*/like"     // 좋아요 취소
                        ).authenticated()


                        /* ==================================================
                           [12] 그 외 모든 요청 차단
                        ================================================== */
                        .anyRequest().denyAll()
                );

        // SecurityContextRepository 연결 -> Spring Security가 자동으로 세션 관리
        http.securityContext(context -> context
                .securityContextRepository(securityContextRepository())
        );

        http.sessionManagement(session -> session
                .sessionFixation().migrateSession()
        );

        // 인증 실패 에러 처리
        http.exceptionHandling(hbc
                -> hbc.authenticationEntryPoint(new AuthEntryPoint())
        );

        return http.build();
    }

    @Bean
    public HttpSessionSecurityContextRepository securityContextRepository() {
        HttpSessionSecurityContextRepository repository = new HttpSessionSecurityContextRepository();
        repository.setSpringSecurityContextKey(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        return repository;
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthService authService,
            PasswordEncoder passwordEncoder
    ) {
        // 레퍼지토리 기반 인증 제공자 설정
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(authService);
        provider.setPasswordEncoder(passwordEncoder); // 비밀번호 검증 인코더 지정
        return new ProviderManager(provider);
    }

    @Bean //인코더
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
