package ee.ria.eudi.qeaa.issuer.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.common.ConsoleNotifier;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import ee.ria.eudi.qeaa.issuer.configuration.properties.IssuerProperties;
import ee.ria.eudi.qeaa.issuer.configuration.properties.IssuerProperties.AuthorizationServer;
import ee.ria.eudi.qeaa.issuer.error.ServiceException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doReturn;

@ExtendWith(MockitoExtension.class)
public class AuthorizationServerMetadataServiceTest {
    public static final String AS_METADATA = """
        {
          "authorization_endpoint": "http://eudi-as.localhost:9000/authorize",
          "token_endpoint": "http://eudi-as.localhost:9000/token",
          "pushed_authorization_request_endpoint": "http://eudi-as.localhost:9000/as/par",
          "issuer": "http://eudi-as.localhost:9000",
          "jwks_uri": "http://eudi-as.localhost:9000/.well-known/jwks.json",
          "response_types_supported": [
            "code"
          ],
          "grant_types_supported": [
            "authorization_code"
          ],
          "code_challenge_methods_supported": [
            "S256"
          ],
          "token_endpoint_auth_methods_supported": [
            "attest_jwt_client_auth"
          ],
          "request_object_signing_alg_values_supported": [
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512"
          ],
          "dpop_signing_alg_values_supported": [
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512"
          ],
          "require_pushed_authorization_requests": true
        }
        """;
    private static final String AS_METADATA_JWK_SET = """
        {
           "keys": [
              {
                 "kty": "EC",
                 "x5t#S256": "fsPlxdKCVobdSbWKY-ehREfssDlbXa-7np2Mg7gObn0",
                 "nbf": 1724836394,
                 "crv": "P-256",
                 "kid": "eudi-as.localhost",
                 "x5c": [
                    "MIIB6TCCAY+gAwIBAgIUUaTaHwmN9QLJ2f3NCMV2faUxhOEwCgYIKoZIzj0EAwQwUDELMAkGA1UEBhMCRUUxEDAOBgNVBAcMB1RhbGxpbm4xEzARBgNVBAoMCmV1ZGktbG9jYWwxGjAYBgNVBAMMEWV1ZGktY2EubG9jYWxob3N0MB4XDTI0MDgyODA5MTMxNFoXDTI1MDgyNjA5MTMxNFowHDEaMBgGA1UEAwwRZXVkaS1hcy5sb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQOTIAaZdA5rz0iX8LUjfhaVnNa6xoEwySH//FGomRpckrp1ZRp8KxtYqL/gxR6dGyXV6fwy7CDy5ObsK+TnJl9o3sweTAfBgNVHSMEGDAWgBTu+lGKSDT708BCLIllivP5oG164DAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIFoDAcBgNVHREEFTATghFldWRpLWFzLmxvY2FsaG9zdDAdBgNVHQ4EFgQUNUF+ERqH3Eif54EIjmaLHkU9/qIwCgYIKoZIzj0EAwQDSAAwRQIhAPyCOmUzZQnJ1Whe6Xqhr1bzVudqrIFGK0JhvNZpy6K+AiAa87s8LXOEGSSLqCKylNYW2rOei/1EaPZQot5dm4u0pg=="
                 ],
                 "x": "DkyAGmXQOa89Il_C1I34WlZzWusaBMMkh__xRqJkaXI",
                 "y": "SunVlGnwrG1iov-DFHp0bJdXp_DLsIPLk5uwr5OcmX0",
                 "exp": 1756199594
              }
           ]
        }
        """;

    @Mock
    IssuerProperties issuerProperties;

    @InjectMocks
    AuthorizationServerMetadataService authorizationServerMetadataService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    protected static final WireMockServer AS_MOCK_SERVER = new WireMockServer(WireMockConfiguration.wireMockConfig()
        .httpDisabled(false)
        .port(9000)
        .notifier(new ConsoleNotifier(true))
    );

    @BeforeAll
    static void setUpAll() {
        AS_MOCK_SERVER.start();
        AS_MOCK_SERVER.stubFor(get(urlEqualTo("/.well-known/openid-configuration"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json; charset=UTF-8")
                .withBody(AS_METADATA)));

        AS_MOCK_SERVER.stubFor(get(urlEqualTo("/.well-known/jwks.json"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json; charset=UTF-8")
                .withBody(AS_METADATA_JWK_SET)));
    }

    @BeforeEach
    public void beforeEachTest() {
        AuthorizationServer as = AuthorizationServer.builder()
            .baseUrl("http://eudi-as.localhost:9000")
            .build();
        doReturn(as).when(issuerProperties).as();
    }

    @Test
    void getJWKSet_WhenJWKSetNotRequested_ThrowsServiceException() {
        ServiceException ex = assertThrows(ServiceException.class, () -> authorizationServerMetadataService.getJWKSet());

        assertThat(ex.getMessage(), equalTo("Unable to get http://eudi-as.localhost:9000 metadata"));
    }

    @Test
    void getMetadata_WhenUpdateMetadata_ReturnsAuthorizationServerMetadata() throws IOException, ParseException, java.text.ParseException {
        authorizationServerMetadataService.updateMetadata();
        AuthorizationServerMetadata metadata = authorizationServerMetadataService.getMetadata();

        assertThat(metadata, notNullValue());
        assertThat(metadata.toString().replaceAll("\\\\", ""), equalTo(objectMapper.readValue(AS_METADATA, JsonNode.class).toString()));
    }

    @Test
    void getJWKSet_WhenUpdateMetadata_ReturnsJWKSet() throws IOException, ParseException, java.text.ParseException {
        authorizationServerMetadataService.updateMetadata();
        JWKSet jwkSet = authorizationServerMetadataService.getJWKSet();

        assertThat(jwkSet, notNullValue());
        assertThat(jwkSet.toString(), equalTo(objectMapper.readValue(AS_METADATA_JWK_SET, JsonNode.class).toString()));
    }
}
