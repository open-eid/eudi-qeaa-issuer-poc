package ee.ria.eudi.qeaa.issuer.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.id.Issuer;
import ee.ria.eudi.qeaa.issuer.BaseTest;
import ee.ria.eudi.qeaa.issuer.service.AuthorizationServerMetadataService;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.core.io.Resource;

import java.io.IOException;

import static ee.ria.eudi.qeaa.issuer.controller.MetadataController.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER_REQUEST_MAPPING;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@SpringBootTest(webEnvironment = RANDOM_PORT)
@RequiredArgsConstructor(onConstructor_ = @Autowired)
@TestMethodOrder(MethodOrderer.MethodName.class)
public class MetadataControllerTest extends BaseTest {
    private final ObjectMapper objectMapper;
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
    void getMetadata_WhenValidRequest_ReturnsHttp200WithMetadata(@Value("classpath:expected_metadata_response.json") Resource expectedMetadata) throws IOException {
        String metadata = objectMapper.readValue(expectedMetadata.getFile(), JsonNode.class).toString();
        given()
            .when()
            .get(WELL_KNOWN_OPENID_CREDENTIAL_ISSUER_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(200)
            .body(equalTo(metadata));
    }
}
