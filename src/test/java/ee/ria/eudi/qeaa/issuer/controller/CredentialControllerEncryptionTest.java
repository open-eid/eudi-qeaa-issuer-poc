package ee.ria.eudi.qeaa.issuer.controller;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.id.Issuer;
import ee.ria.eudi.qeaa.issuer.BaseTest;
import ee.ria.eudi.qeaa.issuer.TestUtils;
import ee.ria.eudi.qeaa.issuer.controller.CredentialRequest.CredentialResponseEncryption;
import ee.ria.eudi.qeaa.issuer.model.CredentialNonce;
import ee.ria.eudi.qeaa.issuer.service.AuthorizationServerMetadataService;
import ee.ria.eudi.qeaa.issuer.util.AccessTokenUtil;
import id.walt.mdoc.doc.MDoc;
import io.restassured.http.ContentType;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import java.text.ParseException;
import java.util.List;
import java.util.stream.IntStream;

import static ee.ria.eudi.qeaa.issuer.controller.CredentialController.CREDENTIAL_REQUEST_MAPPING;
import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@SpringBootTest(webEnvironment = RANDOM_PORT, properties = {"eudi.issuer.credential.encryption.required=true"})
@RequiredArgsConstructor(onConstructor_ = @Autowired)
@TestMethodOrder(MethodOrderer.MethodName.class)
public class CredentialControllerEncryptionTest extends BaseTest {
    @MockBean
    private AuthorizationServerMetadataService asMetadataService;

    private static RSAKey RSA_KEY;
    private static ECKey EC_KEY;

    @BeforeAll
    static void setUpKey() throws JOSEException {
        RSA_KEY = new RSAKeyGenerator(2048).keyUse(KeyUse.ENCRYPTION).generate();
        EC_KEY = new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.ENCRYPTION).generate();
    }

    @BeforeEach
    void setUpMockAsMetadata() {
        Issuer issuer = new Issuer("https://eudi-as.localhost");
        AuthorizationServerMetadata asMetadata = new AuthorizationServerMetadata(issuer);
        asMetadata.setDPoPJWSAlgs(List.of(
            JWSAlgorithm.RS256,
            JWSAlgorithm.RS384,
            JWSAlgorithm.RS512,
            JWSAlgorithm.ES256,
            JWSAlgorithm.ES384,
            JWSAlgorithm.ES512,
            JWSAlgorithm.PS256,
            JWSAlgorithm.PS384,
            JWSAlgorithm.PS512));
        Mockito.when(asMetadataService.getMetadata()).thenReturn(asMetadata);
        Mockito.when(asMetadataService.getJWKSet()).thenReturn(new JWKSet(asSigningKey.toPublicJWK()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"RSA-OAEP", "RSA-OAEP-256"})
    void credentialRequest_WhenValidRsaKeyRequest_ReturnsHttp200WithEncryptedCredential(String alg) throws JOSEException, ParseException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialResponseEncryption credentialResponseEncryption = CredentialResponseEncryption.builder()
            .jwk(RSA_KEY.toPublicJWK().toJSONObject())
            .alg(alg)
            .enc("A128CBC-HS256")
            .build();
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof, credentialResponseEncryption);

        String response = given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType("application/jwt")
            .statusCode(200)
            .extract()
            .asString();

        assertThat(response, notNullValue());
        EncryptedJWT jwt = EncryptedJWT.parse(response);
        assertThat(jwt.getHeader().getAlgorithm().getName(), equalTo(alg));
        RSADecrypter decrypter = new RSADecrypter(RSA_KEY);
        jwt.decrypt(decrypter);
        JWTClaimsSet jwtClaimsSet = jwt.getJWTClaimsSet();

        String credential = jwtClaimsSet.getStringClaim("credential");
        assertThat(credential, notNullValue());
        assertCNonce(jwtClaimsSet.getStringClaim("c_nonce"), jwtClaimsSet.getLongClaim("c_nonce_expires_in"), accessTokenHash, cNonce);
        MDoc mDoc = MDoc.Companion.fromCBORHex(credential);
        assertMsoMDoc(mDoc);
        assertIssuerSignedItems(mDoc);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"})
    void credentialRequest_WhenValidEcKeyRequest_ReturnsHttp200WithEncryptedCredential(String alg) throws JOSEException, ParseException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialResponseEncryption credentialResponseEncryption = CredentialResponseEncryption.builder()
            .jwk(EC_KEY.toPublicJWK().toJSONObject())
            .alg(alg)
            .enc("A128CBC-HS256")
            .build();
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof, credentialResponseEncryption);

        String response = given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType("application/jwt")
            .statusCode(200)
            .extract()
            .asString();

        assertThat(response, notNullValue());
        EncryptedJWT jwt = EncryptedJWT.parse(response);
        assertThat(jwt.getHeader().getAlgorithm().getName(), equalTo(alg));
        ECDHDecrypter decrypter = new ECDHDecrypter(EC_KEY);
        jwt.decrypt(decrypter);
        JWTClaimsSet jwtClaimsSet = jwt.getJWTClaimsSet();

        String credential = jwtClaimsSet.getStringClaim("credential");
        assertThat(credential, notNullValue());
        assertCNonce(jwtClaimsSet.getStringClaim("c_nonce"), jwtClaimsSet.getLongClaim("c_nonce_expires_in"), accessTokenHash, cNonce);
        MDoc mDoc = MDoc.Companion.fromCBORHex(credential);
        assertMsoMDoc(mDoc);
        assertIssuerSignedItems(mDoc);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"})
    void credentialRequest_WhenValidEcKeyRequestWithMultipleKeyProofs_ReturnsHttp200WithEncryptedCredentials(String alg) throws JOSEException, ParseException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        List<ECKey> bindingKeys = IntStream.rangeClosed(0, 4)
            .mapToObj(i -> TestUtils.generateECKey()).toList();
        List<SignedJWT> keyProofs = bindingKeys.stream()
            .map(key -> getJwtKeyProof(getJwtKeyProofClaims(cNonce.getNonce()), key))
            .toList();
        CredentialResponseEncryption credentialResponseEncryption = CredentialResponseEncryption.builder()
            .jwk(EC_KEY.toPublicJWK().toJSONObject())
            .alg(alg)
            .enc("A128CBC-HS256")
            .build();
        CredentialRequest credentialRequest = getCredentialRequest(keyProofs, credentialResponseEncryption);

        String response = given()
            .contentType(ContentType.JSON)
            .header("Authorization", "DPoP " + token)
            .header("DPoP", dPoPProof.serialize())
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType("application/jwt")
            .statusCode(200)
            .extract()
            .asString();

        assertThat(response, notNullValue());
        EncryptedJWT jwt = EncryptedJWT.parse(response);
        assertThat(jwt.getHeader().getAlgorithm().getName(), equalTo(alg));
        ECDHDecrypter decrypter = new ECDHDecrypter(EC_KEY);
        jwt.decrypt(decrypter);
        JWTClaimsSet jwtClaimsSet = jwt.getJWTClaimsSet();
        assertThat(jwtClaimsSet.getStringClaim("credential"), nullValue());
        List<Object> credentials = jwtClaimsSet.getListClaim("credentials");
        assertThat(credentials, notNullValue());
        assertThat(credentials, hasSize(5));
        assertCNonce(jwtClaimsSet.getStringClaim("c_nonce"), jwtClaimsSet.getLongClaim("c_nonce_expires_in"), accessTokenHash, cNonce);
        IntStream.rangeClosed(0, 4).forEach(i -> {
            MDoc mDoc = MDoc.Companion.fromCBORHex((String) credentials.get(i));
            assertMsoMDoc(mDoc, bindingKeys.get(i));
            assertIssuerSignedItems(mDoc);
        });
    }

    @Test
    void credentialRequest_WhenMissingCredentialResponseEncryptionParameter_ReturnsHttp404() throws JOSEException {
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
            .request().body(credentialRequest)
            .when()
            .post(CREDENTIAL_REQUEST_MAPPING)
            .then()
            .assertThat()
            .contentType(APPLICATION_JSON_VALUE)
            .statusCode(400)
            .body("error", equalTo("invalid_encryption_parameters"))
            .body("error_description", equalTo("Missing credential response encryption request parameter"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Missing credential response encryption request parameter");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"aW52YWxpZCB2YWx1ZQ=="})
    void credentialRequest_WhenInvalidCredentialResponseEncryptionKey_ReturnsHttp404(String jwk) throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        CredentialResponseEncryption credentialResponseEncryption = CredentialResponseEncryption.builder()
            .jwk(jwk)
            .alg("RSA-OAEP")
            .enc("A128CBC-HS256")
            .build();
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof, credentialResponseEncryption);

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
            .body("error", equalTo("invalid_encryption_parameters"))
            .body("error_description", equalTo("Invalid credential response encryption key"))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Invalid credential response encryption key");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"unknown", "RSA1_5", "RSA-OAEP-384", "RSA-OAEP-512"})
    void credentialRequest_WhenUnsupportedCredentialResponseEncryptionAlg_ReturnsHttp404(String alg) throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());

        CredentialResponseEncryption credentialResponseEncryption = CredentialResponseEncryption.builder()
            .jwk(RSA_KEY.toPublicJWK().toJSONString())
            .alg(alg)
            .enc("A128CBC-HS256")
            .build();
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof, credentialResponseEncryption);

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
            .body("error", equalTo("invalid_encryption_parameters"))
            .body("error_description", equalTo("Unsupported response encryption algorithm: " + alg))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Unsupported response encryption algorithm: " + alg);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"unknown", "XC20P"})
    void credentialRequest_WhenUnsupportedCredentialResponseEncryptionEnc_ReturnsHttp404(String enc) throws JOSEException {
        SignedJWT accessToken = getSenderConstrainedAccessToken(walletSigningKey);
        String token = accessToken.serialize();
        String accessTokenHash = AccessTokenUtil.computeSHA256(token);
        CredentialNonce cNonce = generateMockNonce(accessTokenHash);
        SignedJWT dPoPProof = getDPoPProof(accessTokenHash);
        SignedJWT credentialJwtKeyProof = getJwtKeyProof(cNonce.getNonce());
        RSAKey rsaKey = new RSAKeyGenerator(2048)
            .keyUse(KeyUse.ENCRYPTION)
            .generate();

        CredentialResponseEncryption credentialResponseEncryption = CredentialResponseEncryption.builder()
            .jwk(rsaKey.toPublicJWK().toJSONString())
            .alg("RSA-OAEP")
            .enc(enc)
            .build();
        CredentialRequest credentialRequest = getCredentialRequest(credentialJwtKeyProof, credentialResponseEncryption);

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
            .body("error", equalTo("invalid_encryption_parameters"))
            .body("error_description", equalTo("Unsupported response encryption encoding: " + enc))
            .body("c_nonce", nullValue())
            .body("c_nonce_expires_in", nullValue());

        assertErrorIsLogged("Service exception: Unsupported response encryption encoding: " + enc);
    }
}
