package net.eramosdezsobroudoze.destiny.ikorarey.security;

import net.eramosdezsobroudoze.destiny.ikorarey.security.converter.CustomRequestEntityConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.RequestEnhancer;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.servlet.Filter;
import java.io.IOException;
import java.util.Arrays;

@Configuration
@EnableOAuth2Client
public class CustomWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomWebSecurityConfigurerAdapter.class);

    private final OAuth2ClientContext oauth2ClientContext;
    private final CustomRequestEntityConverter customRequestEntityConverter;
    private final String xApiKey;

    @Autowired
    public CustomWebSecurityConfigurerAdapter(
            OAuth2ClientContext oauth2ClientContext
            , CustomRequestEntityConverter customRequestEntityConverter
            , @Value("bungie.api-key") String xApiKey) {
        this.oauth2ClientContext = oauth2ClientContext;
        this.customRequestEntityConverter = customRequestEntityConverter;
        this.xApiKey = xApiKey;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http.antMatcher("/**").authorizeRequests().antMatchers("/", "/login**", "/webjars/**", "/error**").permitAll().anyRequest()
                .authenticated().and().exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/")).and().logout()
                .logoutSuccessUrl("/").permitAll().and().csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
                .addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
        // @formatter:on
    }

    private Filter ssoFilter() {
        OAuth2ClientAuthenticationProcessingFilter bungieFilter = new OAuth2ClientAuthenticationProcessingFilter(
                "/login/bungie");
        OAuth2RestTemplate bungieTemplate = new OAuth2RestTemplate(bungie(), oauth2ClientContext);
        bungieFilter.setRestTemplate(bungieTemplate);
        bungieTemplate.setInterceptors(Arrays.asList(new ClientHttpRequestInterceptor() {
            @Override
            public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
                request.getHeaders().add("X-API-Key", xApiKey);
                LOGGER.info("***\nAdded new header:\n{}\n", xApiKey);
                return execution.execute(request, body);
            }
        }));
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(bungieResource().getUserInfoUri(), bungie().getClientId());
        tokenServices.setRestTemplate(bungieTemplate);
        bungieFilter.setTokenServices(tokenServices);
        return bungieFilter;
    }

    @Bean
    @ConfigurationProperties("bungie.client")
    public AuthorizationCodeResourceDetails bungie() {
        return new AuthorizationCodeResourceDetails();
    }

    @Bean
    @ConfigurationProperties("bungie.resource")
    public ResourceServerProperties bungieResource() {
        return new ResourceServerProperties();
    }

    @Bean
    public FilterRegistrationBean<OAuth2ClientContextFilter> oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
        FilterRegistrationBean<OAuth2ClientContextFilter> registration = new FilterRegistrationBean<OAuth2ClientContextFilter>();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }
/*
    @Bean
    @Primary
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient(){
        DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
        accessTokenResponseClient.setRequestEntityConverter(customRequestEntityConverter);

        OAuth2AccessTokenResponseHttpMessageConverter tokenResponseHttpMessageConverter = new OAuth2AccessTokenResponseHttpMessageConverter();
        RestTemplate restTemplate = new RestTemplate(Arrays.asList(new FormHttpMessageConverter(), tokenResponseHttpMessageConverter));
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());

        accessTokenResponseClient.setRestOperations(restTemplate);
        return accessTokenResponseClient;
    }

    @Bean
    @Primary
    public AuthorizationCodeAccessTokenProvider authorizationCodeAccessTokenProvider() {
        final AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider();
        provider.setAuthorizationRequestEnhancer(new RequestEnhancer() {
            @Override
            public void enhance(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource, MultiValueMap<String, String> form, HttpHeaders headers) {
                LOGGER.info("***\nEnhancing request:\n{}\n", resource.toString());
                headers.add("X-API-Key", xApiKey);
            }
        });
        return provider;
    }
*/
}
