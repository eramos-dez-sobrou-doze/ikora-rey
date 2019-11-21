package net.eramosdezsobroudoze.destiny.ikorarey.security.converter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.stereotype.Service;

@Service
public class CustomRequestEntityConverter implements Converter<OAuth2AuthorizationCodeGrantRequest, RequestEntity<?>> {

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomRequestEntityConverter.class);

    private final OAuth2AuthorizationCodeGrantRequestEntityConverter defaultConverter;

    private final String xApiKey;

    @Autowired
    public CustomRequestEntityConverter(@Value("bungie.api-key") String xApiKey) {
        this.xApiKey = xApiKey;
        defaultConverter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();
    }

    @Override
    public RequestEntity<?> convert(OAuth2AuthorizationCodeGrantRequest req) {
        LOGGER.info("***\nConverting request:\n{}\n", req.toString());
        final RequestEntity<?> entity = defaultConverter.convert(req);
        final HttpHeaders headers = entity.getHeaders();
        headers.add("X-API-Key", xApiKey);
        return new RequestEntity<>(entity.getBody(), headers, entity.getMethod(), entity.getUrl());
    }
}
