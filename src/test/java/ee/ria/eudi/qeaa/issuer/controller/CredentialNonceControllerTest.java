package ee.ria.eudi.qeaa.issuer.controller;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.id.Issuer;
import ee.ria.eudi.qeaa.issuer.BaseTest;
import ee.ria.eudi.qeaa.issuer.service.AuthorizationServerMetadataService;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import static ee.ria.eudi.qeaa.issuer.controller.CredentialNonceController.CREDENTIAL_NONCE_REQUEST_MAPPING;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@SpringBootTest(webEnvironment = RANDOM_PORT)
@RequiredArgsConstructor(onConstructor_ = @Autowired)
@TestMethodOrder(MethodOrderer.MethodName.class)
public class CredentialNonceControllerTest extends BaseTest {
    @MockBean
    private AuthorizationServerMetadataService asMetadataService;

    @BeforeEach
    void setUpMockAsMetadata() {
        Issuer issuer = new Issuer("https://eudi-as.localhost");
        AuthorizationServerMetadata asMetadata = new AuthorizationServerMetadata(issuer);
        Mockito.when(asMetadataService.getMetadata()).thenReturn(asMetadata);
        Mockito.when(asMetadataService.getJWKSet()).thenReturn(new JWKSet(asSigningKey.toPublicJWK()));
    }

    @Test
    void nonceRequest_WhenValidRequest_ReturnsHttp200WithCredentialNonceResponse() {
        String ath = DigestUtils.sha256Hex("ath");
        CredentialNonceResponse response = given()
            .contentType(APPLICATION_FORM_URLENCODED_VALUE)
            .request().formParam("ath", ath)
            .when()
            .post(CREDENTIAL_NONCE_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(200)
            .extract()
            .as(CredentialNonceResponse.class);

        assertThat(response, notNullValue());
        assertThat(response.cNonce(), notNullValue());
        assertThat(response.cNonce(), equalTo(credentialNonceRepository.findByAccessTokenHash(ath).getNonce()));
        assertThat(response.cNonceExpiresIn(), equalTo(604800L));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void nonceRequest_WhenValidRequest_ReturnsHttp200WithCredentialNonceResponse(String ath) {
        given()
            .contentType(APPLICATION_FORM_URLENCODED_VALUE)
            .request().formParam("ath", ath)
            .when()
            .post(CREDENTIAL_NONCE_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(400)
            .body("error", equalTo("invalid_request"))
            .body("error_description", equalTo("ath: must not be blank"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("User input exception: nonceRequest -> ath: must not be blank");
    }
}
