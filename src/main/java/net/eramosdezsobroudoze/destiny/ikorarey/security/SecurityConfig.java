package net.eramosdezsobroudoze.destiny.ikorarey.security;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
            .authorizeRequests()
            .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
            .anyRequest().authenticated()
            .and()
            .oauth2Login()
            .loginPage("/login")
            .permitAll();

/*
        http.antMatcher("/**")
                .authorizeRequests()
                .antMatchers("/", "/login**", "/webjars/**", "/error**", "/oauth2", "/auth")
                    .permitAll().anyRequest()
                    .authenticated()
                .and()
                .exceptionHandling()
                .and()
                .oauth2Login()
                .and().logout()
                .logoutSuccessUrl("/").permitAll();
*/
    }
}
