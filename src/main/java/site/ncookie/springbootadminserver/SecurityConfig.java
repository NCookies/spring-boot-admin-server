package site.ncookie.springbootadminserver;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity(debug = true)
public class SecurityConfig {

    private final AdminServerProperties adminServer;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 로그인 성공 시 메인페이지로 redirect
        final SavedRequestAwareAuthenticationSuccessHandler loginSuccessHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        loginSuccessHandler.setTargetUrlParameter("redirectTo");
        loginSuccessHandler.setDefaultTargetUrl(this.adminServer.path("/"));

        http
                .authorizeHttpRequests()
                // 로그인 페이지와 assets 리소스는 누구나 접근할 수 있도록 허용
                .requestMatchers(
                        "/login",
                        "/assets/*"
                ).permitAll()
                // 그 외에는 접근 권한이 필요함
                .anyRequest().authenticated()

                .and()
                // 로그인 URL 및 success handler 설정
                .formLogin().loginPage(this.adminServer.path("/login")).successHandler(loginSuccessHandler)
                // 로그아웃 URL 설정
                .and().logout().logoutUrl("/logout")

                .and()
                // Client 등록을 위한 HTTP-Basic 지원 사용
                .httpBasic()
                .and().csrf()
                // 쿠키를 사용하여 CSRF 보호
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())

                // CSRF 비활성화 URL
                .ignoringRequestMatchers(
                        this.adminServer.path("/instances"),
                        this.adminServer.path("/actuator/**")
                );

        return http.build();
    }
}
