package net.eramosdezsobroudoze.destiny.ikorarey.auth.converter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;

public class CustomRequestEntityConverter implements
        Converter<OAuth2AuthorizationCodeGrantRequest, RequestEntity<?>> {

    private OAuth2AuthorizationCodeGrantRequestEntityConverter defaultConverter;

    private final String xApiKey;

    public CustomRequestEntityConverter(@Value("security.oauth2.client.api-key") String xApiKey) {
        this.xApiKey = xApiKey;
        defaultConverter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();
    }

    @Override
    public RequestEntity<?> convert(OAuth2AuthorizationCodeGrantRequest req) {
        RequestEntity<?> entity = defaultConverter.convert(req);
        final HttpHeaders headers = entity.getHeaders();
        headers.add("X-API-Key", xApiKey);
        return new RequestEntity<>(
            entity.getBody()
            , headers
            , entity.getMethod()
            , entity.getUrl()
        );
    }

}
