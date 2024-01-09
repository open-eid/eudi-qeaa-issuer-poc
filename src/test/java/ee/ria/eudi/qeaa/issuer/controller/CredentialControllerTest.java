package ee.ria.eudi.qeaa.issuer.controller;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPIssuer;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DefaultDPoPSingleUseChecker;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.util.singleuse.AlreadyUsedException;
import com.nimbusds.openid.connect.sdk.Nonce;
import ee.ria.eudi.qeaa.issuer.BaseTest;
import ee.ria.eudi.qeaa.issuer.model.CredentialNonce;
import ee.ria.eudi.qeaa.issuer.model.CredentialRequest;
import ee.ria.eudi.qeaa.issuer.model.CredentialResponse;
import ee.ria.eudi.qeaa.issuer.service.AuthorizationServerMetadataService;
import ee.ria.eudi.qeaa.issuer.util.AccessTokenUtil;
import ee.ria.eudi.qeaa.issuer.validation.AccessTokenValidator;
import ee.ria.eudi.qeaa.issuer.validation.CredentialRequestValidator;
import ee.ria.eudi.qeaa.issuer.validation.DPoPValidator;
import id.walt.mdoc.doc.MDoc;
import io.restassured.http.ContentType;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;

import java.time.Clock;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static ee.ria.eudi.qeaa.issuer.controller.CredentialController.CREDENTIAL_REQUEST_MAPPING;
import static io.restassured.RestAssured.given;
import static java.time.ZoneId.of;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;


@RequiredArgsConstructor(onConstructor_ = @Autowired)
@TestMethodOrder(MethodOrderer.MethodName.class)
class CredentialControllerTest extends BaseTest {

    @MockBean
    private AuthorizationServerMetadataService asMetadataService;
    @SpyBean
    private DPoPValidator dPoPValidator;
    @SpyBean
    private CredentialRequestValidator credentialRequestValidator;
    @SpyBean
    private AccessTokenValidator accessTokenValidator;
    private final DefaultDPoPSingleUseChecker dPoPSingleUseChecker;

    @BeforeEach
    void setUpMockAsMetadata() {
        Issuer issuer = new Issuer("https://eudi-as.localhost");
        AuthorizationServerMetadata asMetadata = new AuthorizationServerMetadata(issuer);
        Mockito.when(asMetadataService.getMetadata()).thenReturn(asMetadata);
        Mockito.when(asMetadataService.getJWKSet()).thenReturn(new JWKSet(asSigningKey.toPublicJWK()));
    }

    @Test
    void credentialRequest_WhenValidRequest_ReturnsHttp200WithIssuedCredential() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        CredentialResponse response = given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(200)
            .extract()
            .as(CredentialResponse.class);

        assertThat(response, notNullValue());
        assertThat(response.format(), equalTo("mso_mdoc"));
        assertThat(response.credential(), notNullValue());
        assertCNonce(response, accessTokenHash, cNonce);
        MDoc mDoc = MDoc.Companion.fromCBORHex(response.credential());
        assertMsoMDoc(mDoc);
        assertIssuerSignedItems(mDoc);
    }

    @Test
    void credentialRequest_WhenNoCredentialNonceForAccessTokenHash_ReturnsHttp400WithNewNonce() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = CredentialNonce.builder()
            .nonce(new Nonce().getValue())
            .issuedAt(Instant.now())
            .accessTokenHash(accessTokenHash)
            .build();
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(400)
            .body("error", equalTo("invalid_proof"))
            .body("error_description", equalTo("Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce."))
            .body("c_nonce", equalTo(credentialNonceRepository.findByAccessTokenHash(accessTokenHash).getNonce()))
            .body("c_nonce_expires_in", equalTo((int) issuerProperties.issuer().cNonceExpiryTime().toSeconds()));

        assertThat(credentialNonceRepository.findByAccessTokenHash(accessTokenHash).getNonce(), not(equalTo(cNonce.getNonce())));
        assertErrorIsLogged("Service exception: Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce.");
    }

    @Test
    void credentialRequest_WhenCredentialNonceExpired_ReturnsHttp400WithNewNonce() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = CredentialNonce.builder()
            .nonce(new Nonce().getValue())
            .issuedAt(Instant.now().minusSeconds(issuerProperties.issuer().cNonceExpiryTime().toSeconds()))
            .accessTokenHash(accessTokenHash)
            .build();
        credentialNonceRepository.save(cNonce);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(400)
            .body("error", equalTo("invalid_proof"))
            .body("error_description", equalTo("Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce."))
            .body("c_nonce", equalTo(credentialNonceRepository.findByAccessTokenHash(accessTokenHash).getNonce()))
            .body("c_nonce_expires_in", equalTo((int) issuerProperties.issuer().cNonceExpiryTime().toSeconds()));

        assertThat(credentialNonceRepository.findByAccessTokenHash(accessTokenHash).getNonce(), not(equalTo(cNonce.getNonce())));
        assertErrorIsLogged("Service exception: Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce.");
    }

    @Test
    void credentialRequest_WhenCredentialNonceFromErrorIsUsed_ReturnsHttp200WithIssuedCredential() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = CredentialNonce.builder()
            .nonce(new Nonce().getValue())
            .issuedAt(Instant.now())
            .accessTokenHash(accessTokenHash)
            .build();
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        String newCNonce = given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(400)
            .body("error", equalTo("invalid_proof"))
            .body("error_description", equalTo("Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce."))
            .body("c_nonce", equalTo(credentialNonceRepository.findByAccessTokenHash(accessTokenHash).getNonce()))
            .body("c_nonce_expires_in", equalTo((int) issuerProperties.issuer().cNonceExpiryTime().toSeconds()))
            .extract().path("c_nonce");

        assertThat(credentialNonceRepository.findByAccessTokenHash(accessTokenHash).getNonce(), not(equalTo(cNonce.getNonce())));
        assertErrorIsLogged("Service exception: Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce.");

        credentialJwtKeyProof = getJwtKeyProof(newCNonce);
        credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        CredentialResponse response = given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(200)
            .extract()
            .as(CredentialResponse.class);

        assertThat(response, notNullValue());
        assertThat(response.format(), equalTo("mso_mdoc"));
        assertThat(response.credential(), notNullValue());
        assertCNonce(response, accessTokenHash, cNonce);
        MDoc mDoc = MDoc.Companion.fromCBORHex(response.credential());
        assertMsoMDoc(mDoc);
        assertIssuerSignedItems(mDoc);
    }

    @Test
    void credentialRequest_WhenAccessTokenSignatureInvalid_ReturnsHttp401() throws JOSEException {
        ECKey invalidAccessTokenSigningKey = new ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.SIGNATURE)
            .keyID(UUID.randomUUID().toString())
            .issueTime(new Date())
            .generate();
        SignedJWT accessToken = new SignedJWT(new JWSHeader.Builder(asSigningKeyJwsAlg)
            .type(JOSEObjectType.JWT)
            .build(), getAccessTokenClaims(Collections.emptyMap(), walletSigningKey.computeThumbprint().toString()));
        accessToken.sign(new ECDSASigner(invalidAccessTokenSigningKey));
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_token"))
            .body("error_description", equalTo("Invalid access token"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Invalid access token --> Signed JWT rejected: Invalid signature");
    }

    @Test
    void credentialRequest_WhenAccessTokenIssuerInvalid_ReturnsHttp401() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(
            Map.of(JWTClaimNames.ISSUER, "https://invalid-issuer.localhost"),
            walletSigningKey.computeThumbprint().toString());
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_token"))
            .body("error_description", equalTo("Invalid access token"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Invalid access token --> JWT iss claim has value https://invalid-issuer.localhost, must be https://eudi-as.localhost");
    }

    @Test
    void credentialRequest_WhenAccessTokenAudienceInvalid_ReturnsHttp401() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(
            Map.of(JWTClaimNames.AUDIENCE, "https://invalid-audience.localhost"),
            walletSigningKey.computeThumbprint().toString());
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_token"))
            .body("error_description", equalTo("Invalid access token"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Invalid access token --> JWT aud claim has value [https://invalid-audience.localhost], must be [https://eudi-issuer.localhost:13443]");
    }

    @Test
    void credentialRequest_WhenAccessTokenCnfClaimMissing_ReturnsHttp401() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(Collections.emptyMap(), null);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_token"))
            .body("error_description", equalTo("Invalid access token"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Invalid access token --> JWT missing required claims: [cnf]");
    }

    @Test
    void credentialRequest_WhenAccessTokenJktClaimEmpty_ReturnsHttp401() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(Collections.emptyMap(), "");
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_token"))
            .body("error_description", equalTo("Invalid access token"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Invalid access token --> Invalid access token jkt claim");
    }

    @Test
    void credentialRequest_WhenAccessTokenExpired_ReturnsHttp401() throws JOSEException {
        Instant currentTime = Instant.now();
        Mockito.when(accessTokenValidator.getSystemClock()).thenReturn(Clock.fixed(currentTime, of("UTC")));
        SignedJWT accessToken = getSenderConstrainedAccessToken(
            Map.of(JWTClaimNames.EXPIRATION_TIME, currentTime.getEpochSecond() - issuerProperties.issuer().maxClockSkew().toSeconds()),
            walletSigningKey.computeThumbprint().toString());
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_token"))
            .body("error_description", equalTo("Invalid access token"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Invalid access token --> Expired JWT");
    }

    @Test
    void credentialRequest_WhenDPoPSignatureInvalid_ReturnsHttp401() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        ECKey invalidDPoPSigningKey = new ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.SIGNATURE)
            .keyID(UUID.randomUUID().toString())
            .issueTime(new Date())
            .generate();
        SignedJWT dPoPProof = new SignedJWT(new JWSHeader.Builder(walletSigningKeyJwsAlg)
            .type(new JOSEObjectType("dpop+jwt"))
            .jwk(walletSigningKey.toPublicJWK())
            .build(), getDPoPProofClaims(accessTokenHash));
        dPoPProof.sign(new ECDSASigner(invalidDPoPSigningKey));

        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_dpop_proof"))
            .body("error_description", equalTo("Invalid DPoP"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Invalid DPoP --> Signed JWT rejected: Invalid signature");
    }

    @Test
    void credentialRequest_WhenDPoPKeyBindingInvalid_ReturnsHttp401() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        ECKey invalidDPoPSigningKey = new ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.SIGNATURE)
            .keyID(UUID.randomUUID().toString())
            .issueTime(new Date())
            .generate();
        SignedJWT dPoPProof = new SignedJWT(new JWSHeader.Builder(walletSigningKeyJwsAlg)
            .type(new JOSEObjectType("dpop+jwt"))
            .jwk(invalidDPoPSigningKey.toPublicJWK())
            .build(), getDPoPProofClaims(accessTokenHash));
        dPoPProof.sign(new ECDSASigner(invalidDPoPSigningKey));

        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_dpop_proof"))
            .body("error_description", equalTo("Invalid DPoP key binding"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Invalid DPoP key binding");
    }

    @Test
    void credentialRequest_WhenDPoPAccessTokenHashInvalid_ReturnsHttp401() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = new SignedJWT(new JWSHeader.Builder(walletSigningKeyJwsAlg)
            .type(new JOSEObjectType("dpop+jwt"))
            .jwk(walletSigningKey.toPublicJWK())
            .build(), getDPoPProofClaims("invalid-access-token-hash"));
        dPoPProof.sign(new ECDSASigner(walletSigningKey));
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_dpop_proof"))
            .body("error_description", equalTo("Invalid DPoP Access Token Hash binding"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Invalid DPoP Access Token Hash binding");
    }

    @Test
    void credentialRequest_WhenDPoPHtuClaimInvalid_ReturnsHttp401() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        JWTClaimsSet dPoPClaims = new JWTClaimsSet.Builder()
            .claim(JWTClaimNames.JWT_ID, new JWTID(40).getValue())
            .claim(JWTClaimNames.ISSUED_AT, Instant.now().getEpochSecond())
            .claim("htm", "POST")
            .claim("htu", issuerProperties.issuer().baseUrl())
            .claim("ath", accessTokenHash)
            .build();
        SignedJWT dPoPProof = new SignedJWT(new JWSHeader.Builder(walletSigningKeyJwsAlg)
            .type(new JOSEObjectType("dpop+jwt"))
            .jwk(walletSigningKey.toPublicJWK())
            .build(), dPoPClaims);
        dPoPProof.sign(new ECDSASigner(walletSigningKey));
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_dpop_proof"))
            .body("error_description", equalTo("Invalid DPoP"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Invalid DPoP --> JWT htu claim has value https://eudi-issuer.localhost:13443, must be https://eudi-issuer.localhost:13443/credential");
    }

    @Test
    void credentialRequest_WhenDPoPHtmClaimInvalid_ReturnsHttp401() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        JWTClaimsSet dPoPClaims = new JWTClaimsSet.Builder()
            .claim(JWTClaimNames.JWT_ID, new JWTID(40).getValue())
            .claim(JWTClaimNames.ISSUED_AT, Instant.now().getEpochSecond())
            .claim("htm", "GET")
            .claim("htu", issuerProperties.issuer().baseUrl() + CREDENTIAL_REQUEST_MAPPING)
            .claim("ath", accessTokenHash)
            .build();
        SignedJWT dPoPProof = new SignedJWT(new JWSHeader.Builder(walletSigningKeyJwsAlg)
            .type(new JOSEObjectType("dpop+jwt"))
            .jwk(walletSigningKey.toPublicJWK())
            .build(), dPoPClaims);
        dPoPProof.sign(new ECDSASigner(walletSigningKey));
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_dpop_proof"))
            .body("error_description", equalTo("Invalid DPoP"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Invalid DPoP --> JWT htm claim has value GET, must be POST");
    }

    @Test
    void credentialRequest_WhenDPoPExpired_ReturnsHttp401() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        Instant currentTime = Instant.now();
        Mockito.when(dPoPValidator.getSystemClock()).thenReturn(Clock.fixed(currentTime, of("UTC")));
        long issueTimeInPast = currentTime.getEpochSecond() - issuerProperties.issuer().dPoPExpiryTime().toSeconds() - issuerProperties.issuer().maxClockSkew().toSeconds();
        JWTClaimsSet dPoPClaims = new JWTClaimsSet.Builder()
            .claim(JWTClaimNames.JWT_ID, new JWTID(40).getValue())
            .claim(JWTClaimNames.ISSUED_AT, issueTimeInPast)
            .claim("htm", "POST")
            .claim("htu", issuerProperties.issuer().baseUrl() + CREDENTIAL_REQUEST_MAPPING)
            .claim("ath", accessTokenHash)
            .build();
        SignedJWT dPoPProof = new SignedJWT(new JWSHeader.Builder(walletSigningKeyJwsAlg)
            .type(new JOSEObjectType("dpop+jwt"))
            .jwk(walletSigningKey.toPublicJWK())
            .build(), dPoPClaims);
        dPoPProof.sign(new ECDSASigner(walletSigningKey));
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_dpop_proof"))
            .body("error_description", equalTo("DPoP expired"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: DPoP expired");
    }

    @Test
    void credentialRequest_WhenDPoPNotYetValid_ReturnsHttp401() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        Instant currentTime = Instant.now();
        Mockito.when(dPoPValidator.getSystemClock()).thenReturn(Clock.fixed(currentTime, of("UTC")));
        long issueTimeInFuture = currentTime.getEpochSecond() + issuerProperties.issuer().maxClockSkew().toSeconds() + 1;
        JWTClaimsSet dPoPClaims = new JWTClaimsSet.Builder()
            .claim(JWTClaimNames.JWT_ID, new JWTID(40).getValue())
            .claim(JWTClaimNames.ISSUED_AT, issueTimeInFuture)
            .claim("htm", "POST")
            .claim("htu", issuerProperties.issuer().baseUrl() + CREDENTIAL_REQUEST_MAPPING)
            .claim("ath", accessTokenHash)
            .build();
        SignedJWT dPoPProof = new SignedJWT(new JWSHeader.Builder(walletSigningKeyJwsAlg)
            .type(new JOSEObjectType("dpop+jwt"))
            .jwk(walletSigningKey.toPublicJWK())
            .build(), dPoPClaims);
        dPoPProof.sign(new ECDSASigner(walletSigningKey));
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_dpop_proof"))
            .body("error_description", equalTo("DPoP not yet valid"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: DPoP not yet valid");
    }

    @Test
    void credentialRequest_WhenDPoPJwsTypeInvalid_ReturnsHttp401() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        JWTClaimsSet dPoPClaims = new JWTClaimsSet.Builder()
            .claim(JWTClaimNames.JWT_ID, new JWTID(40).getValue())
            .claim(JWTClaimNames.ISSUED_AT, Instant.now().getEpochSecond())
            .claim("htm", "POST")
            .claim("htu", issuerProperties.issuer().baseUrl() + CREDENTIAL_REQUEST_MAPPING)
            .claim("ath", accessTokenHash)
            .build();
        SignedJWT dPoPProof = new SignedJWT(new JWSHeader.Builder(walletSigningKeyJwsAlg)
            .type(new JOSEObjectType("jwt"))
            .jwk(walletSigningKey.toPublicJWK())
            .build(), dPoPClaims);
        dPoPProof.sign(new ECDSASigner(walletSigningKey));

        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_dpop_proof"))
            .body("error_description", equalTo("Invalid DPoP"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Invalid DPoP --> JOSE header typ (type) jwt not allowed");
    }

    @Test
    void credentialRequest_WhenDPoPDuplicateHeader_ReturnsHttp401() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_dpop_proof"))
            .body("error_description", equalTo("Duplicate DPoP header"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Duplicate DPoP header");
    }

    @Test
    void credentialRequest_WhenDPoPHeaderMissing_ReturnsHttp401() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_dpop_proof"))
            .body("error_description", equalTo("Missing DPoP header"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Missing DPoP header");
    }

    @Test
    void credentialRequest_WhenDPoPReplay_ReturnsHttp400() throws JOSEException, AlreadyUsedException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);

        JWTID jwtid = new JWTID(40);
        dPoPSingleUseChecker.markAsUsed(Map.entry(new DPoPIssuer(WALLET_CLIENT_ID), jwtid));
        JWTClaimsSet dPoPClaims = new JWTClaimsSet.Builder()
            .claim(JWTClaimNames.JWT_ID, jwtid.getValue())
            .claim(JWTClaimNames.ISSUED_AT, Instant.now().getEpochSecond())
            .claim("htm", "POST")
            .claim("htu", issuerProperties.issuer().baseUrl() + CREDENTIAL_REQUEST_MAPPING)
            .claim("ath", accessTokenHash)
            .build();

        SignedJWT dPoPProof = new SignedJWT(new JWSHeader.Builder(walletSigningKeyJwsAlg)
            .type(new JOSEObjectType("dpop+jwt"))
            .jwk(walletSigningKey.toPublicJWK())
            .build(), dPoPClaims);
        dPoPProof.sign(new ECDSASigner(walletSigningKey));

        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_dpop_proof"))
            .body("error_description", equalTo("DPoP has already been used"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: DPoP has already been used");
    }

    @Test
    void credentialRequest_WhenDPoPAuthorizationDuplicateHeader_ReturnsHttp401() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_token"))
            .body("error_description", equalTo("Duplicate DPoP Authorization header"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Duplicate DPoP Authorization header");
    }

    @Test
    void credentialRequest_WhenDPoPAuthorizationHeaderTypeInvalid_ReturnsHttp401() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_token"))
            .body("error_description", equalTo("Invalid Authorization header type"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Invalid Authorization header type");
    }

    @Test
    void credentialRequest_WhenDPoPAuthorizationHeaderMissing_ReturnsHttp401() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(401)
            .body("error", equalTo("invalid_token"))
            .body("error_description", equalTo("Missing DPoP Authorization header"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Missing DPoP Authorization header");
    }

    @Test
    void credentialRequest_WhenCredentialRequestMissing_ReturnsHttp401() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(400)
            .body("error", equalTo("invalid_credential_request"))
            .body("error_description", equalTo("Missing credential request"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Missing credential request");
    }

    @Test
    void credentialRequest_WhenCredentialRequestFormatUnsupported_ReturnsHttp400() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest.Proof proof = CredentialRequest.Proof.builder()
            .proofType("jwt")
            .jwt(credentialJwtKeyProof.serialize())
            .build();
        CredentialRequest credentialRequest = CredentialRequest.builder()
            .format("unsupported_format")
            .doctype("org.iso.18013.5.1.mDL")
            .proof(proof)
            .build();

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(400)
            .body("error", equalTo("unsupported_credential_format"))
            .body("error_description", equalTo("Unsupported credential format: unsupported_format"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Unsupported credential format: unsupported_format");
    }

    @Test
    void credentialRequest_WhenCredentialRequestDoctypeUnsupported_ReturnsHttp400() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest.Proof proof = CredentialRequest.Proof.builder()
            .proofType("jwt")
            .jwt(credentialJwtKeyProof.serialize())
            .build();
        CredentialRequest credentialRequest = CredentialRequest.builder()
            .format("mso_mdoc")
            .doctype("unsupported_doctype")
            .proof(proof)
            .build();

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(400)
            .body("error", equalTo("unsupported_credential_type"))
            .body("error_description", equalTo("Unsupported credential type: unsupported_doctype"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Unsupported credential type: unsupported_doctype");
    }

    @Test
    void credentialRequest_WhenCredentialRequestProofMissing_ReturnsHttp400() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        CredentialRequest credentialRequest = CredentialRequest.builder()
            .format("mso_mdoc")
            .doctype("org.iso.18013.5.1.mDL")
            .build();

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(400)
            .body("error", equalTo("invalid_credential_request"))
            .body("error_description", equalTo("Missing Key Proof"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Missing Key Proof");
    }

    @Test
    void credentialRequest_WhenCredentialRequestKeyProofNonceInvalid_ReturnsHttp400() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof("invalid-credential-nonce");
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(400)
            .body("error", equalTo("invalid_proof"))
            .body("error_description", equalTo("Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce."))
            .body("c_nonce", equalTo(credentialNonceRepository.findByAccessTokenHash(accessTokenHash).getNonce()))
            .body("c_nonce_expires_in", equalTo((int) issuerProperties.issuer().cNonceExpiryTime().toSeconds()));

        assertThat(credentialNonceRepository.findByAccessTokenHash(accessTokenHash).getNonce(), not(equalTo(cNonce.getNonce())));
        assertErrorIsLogged("Service exception: Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce.");
    }

    @Test
    void credentialRequest_WhenCredentialRequestKeyProofTypeInvalid_ReturnsHttp400() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = new SignedJWT(new JWSHeader.Builder(walletSigningKeyJwsAlg)
            .type(new JOSEObjectType("invalid-proof-type"))
            .jwk(walletSigningKey.toPublicJWK())
            .build(), getJwtKeyProofClaims(cNonce.getNonce()));
        credentialJwtKeyProof.sign(new ECDSASigner(walletSigningKey));
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(400)
            .body("error", equalTo("invalid_proof"))
            .body("error_description", equalTo("Invalid Key Proof"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Invalid Key Proof --> JOSE header typ (type) invalid-proof-type not allowed");
    }

    @Test
    void credentialRequest_WhenCredentialRequestKeyProofSignatureInvalid_ReturnsHttp400() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        ECKey invalidKeyProofSigningKey = new ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.SIGNATURE)
            .keyID(UUID.randomUUID().toString())
            .issueTime(new Date())
            .generate();
        SignedJWT credentialJwtKeyProof = new SignedJWT(new JWSHeader.Builder(walletSigningKeyJwsAlg)
            .type(new JOSEObjectType("openid4vci-proof+jwt"))
            .jwk(walletSigningKey.toPublicJWK())
            .build(), getJwtKeyProofClaims(cNonce.getNonce()));
        credentialJwtKeyProof.sign(new ECDSASigner(invalidKeyProofSigningKey));
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(400)
            .body("error", equalTo("invalid_proof"))
            .body("error_description", equalTo("Invalid Key Proof"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Invalid Key Proof --> Signed JWT rejected: Invalid signature");
    }

    @Test
    void credentialRequest_WhenCredentialRequestKeyProofJwkHeaderMissing_ReturnsHttp400() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = new SignedJWT(new JWSHeader.Builder(walletSigningKeyJwsAlg)
            .type(new JOSEObjectType("openid4vci-proof+jwt"))
            .build(), getJwtKeyProofClaims(cNonce.getNonce()));
        credentialJwtKeyProof.sign(new ECDSASigner(walletSigningKey));
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(400)
            .body("error", equalTo("invalid_proof"))
            .body("error_description", equalTo("Invalid Key Proof"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Invalid Key Proof --> Missing JWS jwk header parameter");
    }

    @Test
    void credentialRequest_WhenCredentialRequestKeyProofTypeUnsupported_ReturnsHttp400() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialRequest.Proof proof = CredentialRequest.Proof.builder()
            .proofType("unsupported_proof_type")
            .jwt(credentialJwtKeyProof.serialize())
            .build();
        CredentialRequest credentialRequest = CredentialRequest.builder()
            .format("mso_mdoc")
            .doctype("org.iso.18013.5.1.mDL")
            .proof(proof)
            .build();

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(400)
            .body("error", equalTo("invalid_credential_request"))
            .body("error_description", equalTo("Unsupported Key Proof type: unsupported_proof_type"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Unsupported Key Proof type: unsupported_proof_type");
    }

    @Test
    void credentialRequest_WhenCredentialRequestKeyProofExpired_ReturnsHttp400() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        Instant currentTime = Instant.now();
        Mockito.when(credentialRequestValidator.getSystemClock()).thenReturn(Clock.fixed(currentTime, of("UTC")));
        long issueTimeInPast = currentTime.getEpochSecond() - issuerProperties.issuer().keyProofExpiryTime().toSeconds() - issuerProperties.issuer().maxClockSkew().toSeconds();
        JWTClaimsSet keyProofClaims = new JWTClaimsSet.Builder()
            .claim(JWTClaimNames.ISSUER, "https://eudi-wallet.localhost")
            .claim(JWTClaimNames.AUDIENCE, issuerProperties.issuer().baseUrl())
            .claim(JWTClaimNames.ISSUED_AT, issueTimeInPast)
            .claim("nonce", cNonce.getNonce())
            .build();
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(keyProofClaims);
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(400)
            .body("error", equalTo("invalid_proof"))
            .body("error_description", equalTo("Key Proof expired"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Key Proof expired");
    }

    @Test
    void credentialRequest_WhenCredentialRequestKeyProofNotYetValid_ReturnsHttp400() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        Instant currentTime = Instant.now();
        Mockito.when(credentialRequestValidator.getSystemClock()).thenReturn(Clock.fixed(currentTime, of("UTC")));
        long issueTimeInFuture = currentTime.getEpochSecond() + issuerProperties.issuer().maxClockSkew().toSeconds() + 1;
        JWTClaimsSet keyProofClaims = new JWTClaimsSet.Builder()
            .claim(JWTClaimNames.ISSUER, "https://eudi-wallet.localhost")
            .claim(JWTClaimNames.AUDIENCE, issuerProperties.issuer().baseUrl())
            .claim(JWTClaimNames.ISSUED_AT, issueTimeInFuture)
            .claim("nonce", cNonce.getNonce())
            .build();
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(keyProofClaims);
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(400)
            .body("error", equalTo("invalid_proof"))
            .body("error_description", equalTo("Key Proof not yet valid"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Key Proof not yet valid");
    }

    @Test
    void credentialRequest_WhenCredentialRequestKeyProofIssuerInvalid_ReturnsHttp400() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        JWTClaimsSet keyProofClaims = new JWTClaimsSet.Builder()
            .claim(JWTClaimNames.ISSUER, "https://invalid-issuer.localhost")
            .claim(JWTClaimNames.AUDIENCE, issuerProperties.issuer().baseUrl())
            .claim(JWTClaimNames.ISSUED_AT, Instant.now().getEpochSecond())
            .claim("nonce", cNonce.getNonce())
            .build();
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(keyProofClaims);
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(400)
            .body("error", equalTo("invalid_proof"))
            .body("error_description", equalTo("Invalid Key Proof"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Invalid Key Proof --> JWT iss claim has value https://invalid-issuer.localhost, must be https://eudi-wallet.localhost");
    }

    @Test
    void credentialRequest_WhenCredentialRequestKeyProofAudienceInvalid_ReturnsHttp400() throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        JWTClaimsSet keyProofClaims = new JWTClaimsSet.Builder()
            .claim(JWTClaimNames.ISSUER, "https://eudi-wallet.localhost")
            .claim(JWTClaimNames.AUDIENCE, "https://invalid-audience.localhost")
            .claim(JWTClaimNames.ISSUED_AT, Instant.now().getEpochSecond())
            .claim("nonce", cNonce.getNonce())
            .build();
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(keyProofClaims);
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof);

        given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(400)
            .body("error", equalTo("invalid_proof"))
            .body("error_description", equalTo("Invalid Key Proof"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Invalid Key Proof --> JWT aud claim has value [https://invalid-audience.localhost], must be [https://eudi-issuer.localhost:13443]");
    }
}
