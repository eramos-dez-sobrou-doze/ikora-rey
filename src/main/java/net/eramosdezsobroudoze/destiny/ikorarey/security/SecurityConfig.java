package net.eramosdezsobroudoze.destiny.ikorarey.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

//@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
/*
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .oauth2Login();
*/

        http.antMatcher("/**")
                .authorizeRequests()
                .antMatchers("/login**", "/webjars/**", "/error**", "/oauth2")
                .permitAll().anyRequest()
                .authenticated()
                .and()
                .exceptionHandling()
                .and()
                .oauth2Login()
                .loginPage("/login")
                .and().logout()
                .logoutSuccessUrl("/").permitAll();

    }

}
