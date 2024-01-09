package ee.ria.eudi.qeaa.issuer.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
import ee.ria.eudi.qeaa.issuer.configuration.properties.IssuerProperties;
import ee.ria.eudi.qeaa.issuer.error.ErrorCode;
import ee.ria.eudi.qeaa.issuer.error.ServiceException;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;

import static com.nimbusds.jose.jwk.source.RemoteJWKSet.DEFAULT_HTTP_SIZE_LIMIT;
import static com.nimbusds.oauth2.sdk.GrantType.AUTHORIZATION_CODE;
import static com.nimbusds.oauth2.sdk.ResponseType.CODE;
import static com.nimbusds.oauth2.sdk.WellKnownPathComposeStrategy.POSTFIX;
import static com.nimbusds.oauth2.sdk.util.CollectionUtils.contains;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizationServerMetadataService {
    private final IssuerProperties issuerProperties;
    private final AtomicReference<AuthorizationServerMetadata> authorizationServerMetadataAtomicReference = new AtomicReference<>();
    private final AtomicReference<JWKSet> jwkSetAtomicReference = new AtomicReference<>();
    private final SslBundles sslBundles;
    private SSLContext sslContext;

    @PostConstruct
    private void setupSslContext() {
        sslContext = sslBundles.getBundle("eudi-issuer").createSslContext();
    }

    public AuthorizationServerMetadata getMetadata() {
        AuthorizationServerMetadata metadata = authorizationServerMetadataAtomicReference.get();
        if (metadata == null) {
            throw new ServiceException(ErrorCode.SERVICE_EXCEPTION, "Unable to get %s metadata".formatted(issuerProperties.as().baseUrl()));
        }
        return metadata;
    }

    public JWKSet getJWKSet() {
        JWKSet jwkSet = jwkSetAtomicReference.get();
        if (jwkSet == null) {
            throw new ServiceException(ErrorCode.SERVICE_EXCEPTION, "Unable to get %s metadata".formatted(issuerProperties.as().baseUrl()));
        }
        return jwkSet;
    }

    @Scheduled(fixedRateString = "${eudi.as.metadata.interval:PT24H}")
    @Retryable(maxAttemptsExpression = "${eudi.as.metadata.max-attempts:1440}",
        backoff = @Backoff(delayExpression = "${eudi.as.metadata.backoff-delay-milliseconds:1000}",
            maxDelayExpression = "${eudi.as.metadata.backoff-max-delay-milliseconds:60000}",
            multiplierExpression = "${eudi.as.metadata.backoff-multiplier:1.1}"))
    public void updateMetadata() throws IOException, ParseException, java.text.ParseException {
        log.info("Updating {} metadata", issuerProperties.as().baseUrl());
        AuthorizationServerMetadata metadata = requestMetadata();
        JWKSet jwkSet = requestJWKSet(metadata);
        authorizationServerMetadataAtomicReference.set(metadata);
        jwkSetAtomicReference.set(jwkSet);
    }

    private AuthorizationServerMetadata requestMetadata() throws IOException, ParseException {
        String issuerUrl = issuerProperties.as().baseUrl();
        Issuer issuer = new Issuer(issuerUrl);
        OIDCProviderConfigurationRequest request = new OIDCProviderConfigurationRequest(issuer, POSTFIX);
        HTTPRequest httpRequest = request.toHTTPRequest();
        httpRequest.setSSLSocketFactory(sslContext.getSocketFactory());
        HTTPResponse httpResponse = httpRequest.send();
        JSONObject contentAsJSONObject = httpResponse.getBodyAsJSONObject();
        AuthorizationServerMetadata metadata = AuthorizationServerMetadata.parse(contentAsJSONObject);
        validateMetadata(issuerUrl, metadata);
        return metadata;
    }

    private JWKSet requestJWKSet(AuthorizationServerMetadata metadata) throws IOException, java.text.ParseException {
        DefaultResourceRetriever rr = new DefaultResourceRetriever(
            20000,
            20000,
            DEFAULT_HTTP_SIZE_LIMIT,
            true,
            sslContext.getSocketFactory());
        Resource resource = rr.retrieveResource(metadata.getJWKSetURI().toURL());
        return JWKSet.parse(resource.getContent());
    }

    private void validateMetadata(String issuerUrl, AuthorizationServerMetadata metadata) throws ServiceException {
        String metadataIssuer = metadata.getIssuer().getValue();

        if (!issuerUrl.equals(metadataIssuer))
            throw new ServiceException(String.format("Expected OIDC Issuer '%s' does not match published issuer '%s'", issuerUrl, metadataIssuer));
        if (metadata.getAuthorizationEndpointURI() == null || metadata.getAuthorizationEndpointURI().toString().isBlank())
            throw new ServiceException("The authorization endpoint URI must not be null/empty");
        if (metadata.getTokenEndpointURI() == null || metadata.getTokenEndpointURI().toString().isBlank())
            throw new ServiceException("The token endpoint URI must not be null/empty");
        if (metadata.getPushedAuthorizationRequestEndpointURI() == null || metadata.getPushedAuthorizationRequestEndpointURI().toString().isBlank())
            throw new ServiceException("The PAR endpoint URI must not be null/empty");
        if (metadata.getJWKSetURI() == null || metadata.getJWKSetURI().toString().isBlank())
            throw new ServiceException("The JWK Set endpoint URI must not be null/empty");
        if (!contains(metadata.getDPoPJWSAlgs(), JWSAlgorithm.ES256)) // TODO: Derive from issuer signing key
            throw new ServiceException(String.format("Metadata DPoP token JWS algorithms can not be null and must contain only '%s'", JWSAlgorithm.ES256));
        if (!contains(metadata.getCodeChallengeMethods(), CodeChallengeMethod.S256))
            throw new ServiceException(String.format("Metadata DPoP token JWS algorithms can not be null and must contain only '%s'", CodeChallengeMethod.S256));
        if (!contains(metadata.getResponseTypes(), CODE) || metadata.getResponseTypes().size() != 1)
            throw new ServiceException(String.format("Metadata response types can not be null and must contain only '%s'", CODE));
        if (!contains(metadata.getGrantTypes(), AUTHORIZATION_CODE))
            throw new ServiceException(String.format("Metadata grant types can not be null and must contain: '%s'", AUTHORIZATION_CODE));
        if (!contains(metadata.getTokenEndpointAuthMethods(), new ClientAuthenticationMethod("attest_jwt_client_auth")))
            throw new ServiceException("Metadata token endpoint auth methods can not be null and must contain 'attest_jwt_client_auth'");
    }
}
