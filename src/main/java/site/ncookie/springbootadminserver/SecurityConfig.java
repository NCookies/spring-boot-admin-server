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
        final SavedRequestAwareAuthenticationSuccessHandler loginSuccessHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        loginSuccessHandler.setTargetUrlParameter("redirectTo");
        loginSuccessHandler.setDefaultTargetUrl(this.adminServer.path("/"));

        http
                .authorizeHttpRequests()
                .requestMatchers(
                        "/login",
                        "/assets/*"
                ).permitAll()
                .anyRequest().authenticated()

                .and()
                .formLogin().loginPage(this.adminServer.path("/login")).successHandler(loginSuccessHandler)
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
