package ee.ria.eudi.qeaa.issuer;

import COSE.AlgorithmID;
import COSE.OneKey;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.upokecenter.cbor.CBORObject;
import ee.ria.eudi.qeaa.issuer.configuration.properties.IssuerProperties;
import ee.ria.eudi.qeaa.issuer.controller.CredentialRequest;
import ee.ria.eudi.qeaa.issuer.controller.CredentialRequest.CredentialRequestBuilder;
import ee.ria.eudi.qeaa.issuer.controller.CredentialRequest.CredentialResponseEncryption;
import ee.ria.eudi.qeaa.issuer.controller.CredentialRequest.Proof;
import ee.ria.eudi.qeaa.issuer.controller.CredentialResponse;
import ee.ria.eudi.qeaa.issuer.model.CredentialNonce;
import ee.ria.eudi.qeaa.issuer.repository.CredentialNonceRepository;
import ee.ria.eudi.qeaa.issuer.service.CredentialNamespace;
import id.walt.mdoc.COSECryptoProviderKeyInfo;
import id.walt.mdoc.SimpleCOSECryptoProvider;
import id.walt.mdoc.cose.COSESign1;
import id.walt.mdoc.dataelement.MapElement;
import id.walt.mdoc.dataelement.StringElement;
import id.walt.mdoc.doc.MDoc;
import id.walt.mdoc.issuersigned.IssuerSigned;
import id.walt.mdoc.issuersigned.IssuerSignedItem;
import id.walt.mdoc.mso.MSO;
import io.restassured.RestAssured;
import io.restassured.builder.RequestSpecBuilder;
import io.restassured.filter.log.RequestLoggingFilter;
import io.restassured.filter.log.ResponseLoggingFilter;
import kotlinx.datetime.LocalDate;
import lombok.SneakyThrows;
import org.bouncycastle.util.encoders.Hex;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.Resource;
import org.springframework.test.context.ActiveProfiles;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import static ee.ria.eudi.qeaa.issuer.configuration.MDocConfiguration.KEY_ID_ISSUER;
import static ee.ria.eudi.qeaa.issuer.controller.CredentialController.CREDENTIAL_REQUEST_MAPPING;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_BIRTH_DATE;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_DOCUMENT_NUMBER;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_DRIVING_PRIVILEGES;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_EXPIRY_DATE;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_FAMILY_NAME;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_GIVEN_NAME;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_ISSUE_DATE;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_ISSUING_AUTHORITY;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_ISSUING_COUNTRY;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_PORTRAIT;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_UN_DISTINGUISHING_SIGN;
import static io.restassured.config.RedirectConfig.redirectConfig;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;

@Import(IssuerTestConfiguration.class)
@ActiveProfiles("test")
public abstract class BaseTest extends BaseTestLoggingAssertion {
    public static final String WALLET_CLIENT_ID = "https://eudi-wallet.localhost";
    @LocalServerPort
    protected int port;

    @Autowired
    protected CredentialNonceRepository credentialNonceRepository;

    @Autowired
    protected IssuerProperties issuerProperties;

    @Autowired
    protected ECKey asSigningKey;

    @Autowired
    protected JWSAlgorithm asSigningKeyJwsAlg;

    @Autowired
    protected ECKey walletSigningKey;

    @Autowired
    protected JWSAlgorithm walletSigningKeyJwsAlg;

    @Autowired
    @Qualifier("issuerTrustedRootCAs")
    protected List<X509Certificate> issuerTrustedRootCAs;

    @Value("classpath:subject_portrait.hex")
    private Resource subjectPortrait;

    @BeforeAll
    static void setUp() {
        RestAssured.filters(new RequestLoggingFilter(), new ResponseLoggingFilter());
        RestAssured.config = RestAssured.config().redirect(redirectConfig().followRedirects(false));
        RestAssured.requestSpecification = new RequestSpecBuilder()
            .setBaseUri("https://localhost")
            .setRelaxedHTTPSValidation()
            .build();
    }

    @BeforeEach
    void setUpBeforeEach() {
        RestAssured.requestSpecification.port(port);
    }

    protected void assertCNonce(CredentialResponse response, String accessTokenHash, CredentialNonce expectedCredentialNonce) {
        assertCNonce(response.cNonce(), response.cNonceExpiresIn(), accessTokenHash, expectedCredentialNonce);
    }

    protected void assertCNonce(String cNonce, Long cNonceExpiresIn, String accessTokenHash, CredentialNonce expectedCredentialNonce) {
        CredentialNonce newCNonce = credentialNonceRepository.findByAccessTokenHash(accessTokenHash);
        assertThat(cNonce, notNullValue());
        assertThat(cNonceExpiresIn, notNullValue());
        assertThat(newCNonce, notNullValue());
        assertThat(newCNonce.getNonce(), notNullValue());
        assertThat(newCNonce.getNonce(), not(equalTo(expectedCredentialNonce.getNonce())));
        assertThat(newCNonce.getNonce(), equalTo(cNonce));
        assertThat(newCNonce.getIssuedAt(), notNullValue());
        assertThat(newCNonce.getIssuedAt(), greaterThan(expectedCredentialNonce.getIssuedAt()));
    }

    protected void assertMsoMDoc(MDoc mDoc) {
        assertMsoMDoc(mDoc, walletSigningKey);
    }

    @SneakyThrows
    protected void assertMsoMDoc(MDoc mDoc, ECKey bindingKey) {
        assertThat(mDoc.verifyDocType(), is(true));
        assertThat(mDoc.verifyValidity(), is(true));
        assertThat(mDoc.verifyIssuerSignedItems(), is(true));
        SimpleCOSECryptoProvider issuerCryptoProvider = getIssuerCryptoProvider(mDoc);
        assertThat(mDoc.verifyCertificate(issuerCryptoProvider, KEY_ID_ISSUER), is(true));
        assertThat(mDoc.verifySignature(issuerCryptoProvider, KEY_ID_ISSUER), is(true));
        MSO mso = mDoc.getMSO();
        assertThat(mso, notNullValue());
        assertThat(mso.getDeviceKeyInfo(), notNullValue());
        MapElement deviceKey = mso.getDeviceKeyInfo().getDeviceKey();
        assertThat(deviceKey, notNullValue());
        PublicKey devicePublicKey = new OneKey(CBORObject.DecodeFromBytes(deviceKey.toCBOR())).AsPublicKey();
        assertThat(devicePublicKey, equalTo(bindingKey.toPublicKey()));
    }

    protected SimpleCOSECryptoProvider getIssuerCryptoProvider(MDoc mDoc) {
        List<X509Certificate> x5Chain = getX5Chain(mDoc);
        X509Certificate issuerCert = x5Chain.getFirst();
        PublicKey publicKey = issuerCert.getPublicKey();
        COSECryptoProviderKeyInfo issuerKeyInfo = new COSECryptoProviderKeyInfo(KEY_ID_ISSUER,
            AlgorithmID.ECDSA_256, publicKey, null, x5Chain, issuerTrustedRootCAs);
        return new SimpleCOSECryptoProvider(List.of(issuerKeyInfo));
    }

    @SneakyThrows
    @SuppressWarnings("unchecked")
    protected List<X509Certificate> getX5Chain(MDoc mDoc) {
        IssuerSigned issuerSigned = mDoc.getIssuerSigned();
        COSESign1 issuerAuth = Objects.requireNonNull(issuerSigned.getIssuerAuth());
        byte[] x5Chain = Objects.requireNonNull(issuerAuth.getX5Chain());
        ByteArrayInputStream x5CainInputStream = new ByteArrayInputStream(x5Chain);
        return (List<X509Certificate>) CertificateFactory.getInstance("X509").generateCertificates(x5CainInputStream);
    }

    @SneakyThrows
    @SuppressWarnings("unchecked")
    protected void assertIssuerSignedItems(MDoc mDoc) {
        List<IssuerSignedItem> issuerSignedItems = mDoc.getIssuerSignedItems(CredentialNamespace.ORG_ISO_18013_5_1.getUri());
        Map<String, Object> claims = issuerSignedItems.stream()
            .collect(Collectors.toMap(i -> i.getElementIdentifier().getValue(), i -> i.getElementValue().getInternalValue()));

        assertThat(claims.get(ORG_ISO_18013_5_1_FAMILY_NAME.getUri()), is("Männik"));
        assertThat(claims.get(ORG_ISO_18013_5_1_GIVEN_NAME.getUri()), is("Mari-Liis"));
        assertThat(claims.get(ORG_ISO_18013_5_1_BIRTH_DATE.getUri()), is(LocalDate.Companion.parse("1979-12-24", LocalDate.Formats.INSTANCE.getISO())));
        assertThat(claims.get(ORG_ISO_18013_5_1_ISSUE_DATE.getUri()), is(LocalDate.Companion.parse("2020-12-30", LocalDate.Formats.INSTANCE.getISO())));
        assertThat(claims.get(ORG_ISO_18013_5_1_EXPIRY_DATE.getUri()), is(LocalDate.Companion.parse("2028-12-30", LocalDate.Formats.INSTANCE.getISO())));
        assertThat(claims.get(ORG_ISO_18013_5_1_ISSUING_COUNTRY.getUri()), is("EE"));
        assertThat(claims.get(ORG_ISO_18013_5_1_ISSUING_AUTHORITY.getUri()), is("ARK"));
        assertThat(claims.get(ORG_ISO_18013_5_1_DOCUMENT_NUMBER.getUri()), is("ET000000"));
        assertThat((List<String>) claims.get(ORG_ISO_18013_5_1_DRIVING_PRIVILEGES.getUri()), Matchers.containsInRelativeOrder(new StringElement("A"), new StringElement("B")));
        assertThat(claims.get(ORG_ISO_18013_5_1_UN_DISTINGUISHING_SIGN.getUri()), is("EST"));
        assertThat(claims.get(ORG_ISO_18013_5_1_PORTRAIT.getUri()), is(Hex.decode(subjectPortrait.getContentAsString(StandardCharsets.UTF_8))));
    }

    protected CredentialNonce generateMockNonce(String accessTokenHash) {
        return credentialNonceRepository.save(CredentialNonce.builder()
            .nonce(new Nonce().getValue())
            .issuedAt(Instant.now())
            .accessTokenHash(accessTokenHash)
            .build());
    }

    protected SignedJWT getSenderConstrainedAccessToken(JWK dPoPKey) throws JOSEException {
        return getSenderConstrainedAccessToken(Collections.emptyMap(), dPoPKey.computeThumbprint().toString());
    }

    protected SignedJWT getSenderConstrainedAccessToken(Map<String, Object> overrideClaims, String dPoPKeyThumbprint) throws JOSEException {
        SignedJWT accessToken = new SignedJWT(new JWSHeader.Builder(asSigningKeyJwsAlg)
            .type(new JOSEObjectType("at+jwt"))
            .build(), getAccessTokenClaims(overrideClaims, dPoPKeyThumbprint));
        accessToken.sign(new ECDSASigner(asSigningKey));
        return accessToken;
    }

    protected JWTClaimsSet getAccessTokenClaims(Map<String, Object> overrideClaims, String dPoPKeyThumbprint) {
        long issuedAt = Instant.now().getEpochSecond();
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
            .claim(JWTClaimNames.ISSUER, "https://eudi-as.localhost")
            .claim(JWTClaimNames.SUBJECT, "60001019906")
            .claim(JWTClaimNames.AUDIENCE, "https://eudi-issuer.localhost:13443")
            .claim(JWTClaimNames.ISSUED_AT, issuedAt)
            .claim(JWTClaimNames.EXPIRATION_TIME, issuedAt + 60)
            .claim("client_id", WALLET_CLIENT_ID)
            .claim("authorization_details", List.of(Map.of(
                "type", "openid_credential",
                "format", "mso_mdoc",
                "doctype", "org.iso.18013.5.1.mDL"
            )));
        overrideClaims.forEach(builder::claim);
        if (dPoPKeyThumbprint != null) {
            builder.claim("cnf", Map.of("jkt", dPoPKeyThumbprint));
        }
        return builder.build();
    }

    protected SignedJWT getDPoPProof(String accessTokenHash) throws JOSEException {
        SignedJWT dPoPProof = new SignedJWT(new JWSHeader.Builder(walletSigningKeyJwsAlg)
            .type(new JOSEObjectType("dpop+jwt"))
            .jwk(walletSigningKey.toPublicJWK())
            .build(), getDPoPProofClaims(accessTokenHash));
        dPoPProof.sign(new ECDSASigner(walletSigningKey));
        return dPoPProof;
    }

    protected JWTClaimsSet getDPoPProofClaims(String accessTokenHash) {
        JWTID jti = new JWTID(40);
        return new JWTClaimsSet.Builder()
            .claim(JWTClaimNames.JWT_ID, jti.getValue())
            .claim(JWTClaimNames.ISSUED_AT, Instant.now().getEpochSecond())
            .claim("htm", "POST")
            .claim("htu", issuerProperties.issuer().baseUrl() + CREDENTIAL_REQUEST_MAPPING)
            .claim("ath", accessTokenHash)
            .build();
    }

    protected SignedJWT getJwtKeyProof(String cNonce) {
        return getJwtKeyProof(getJwtKeyProofClaims(cNonce));
    }

    protected SignedJWT getJwtKeyProof(JWTClaimsSet claimsSet) {
        return getJwtKeyProof(claimsSet, walletSigningKey);
    }

    @SneakyThrows
    protected SignedJWT getJwtKeyProof(JWTClaimsSet claimsSet, ECKey ecKey) {
        SignedJWT jwtKeyProof = new SignedJWT(new JWSHeader.Builder(TestUtils.getJwsAlgorithm(ecKey.getCurve()))
            .type(new JOSEObjectType("openid4vci-proof+jwt"))
            .jwk(ecKey.toPublicJWK())
            .build(), claimsSet);
        jwtKeyProof.sign(new ECDSASigner(ecKey));
        return jwtKeyProof;
    }

    protected JWTClaimsSet getJwtKeyProofClaims(String cNonce) {
        return new JWTClaimsSet.Builder()
            .claim(JWTClaimNames.ISSUER, "https://eudi-wallet.localhost")
            .claim(JWTClaimNames.AUDIENCE, issuerProperties.issuer().baseUrl())
            .claim(JWTClaimNames.ISSUED_AT, Instant.now().getEpochSecond())
            .claim("nonce", cNonce)
            .build();
    }

    protected CredentialRequest getCredentialRequest(SignedJWT credentialJwtKeyProof) {
        return getCredentialRequest(List.of(credentialJwtKeyProof));
    }

    protected CredentialRequest getCredentialRequest(SignedJWT credentialJwtKeyProof, CredentialResponseEncryption credentialResponseEncryption) {
        return getCredentialRequest(List.of(credentialJwtKeyProof), credentialResponseEncryption);
    }

    protected CredentialRequest getCredentialRequest(List<SignedJWT> credentialJwtKeyProofs) {
        return getCredentialRequest(credentialJwtKeyProofs, null);
    }

    protected CredentialRequest getCredentialRequest(List<SignedJWT> credentialJwtKeyProofs, CredentialResponseEncryption credentialResponseEncryption) {
        CredentialRequestBuilder requestBuilder = CredentialRequest.builder()
            .format("mso_mdoc")
            .doctype("org.iso.18013.5.1.mDL")
            .credentialResponseEncryption(credentialResponseEncryption);

        List<Proof> keyProofs = getCredentialKeyProofs(credentialJwtKeyProofs);
        if (keyProofs.size() == 1) {
            return requestBuilder.proof(keyProofs.getFirst()).build();
        } else {
            return requestBuilder.proofs(keyProofs).build();
        }
    }

    private List<Proof> getCredentialKeyProofs(List<SignedJWT> credentialJwtKeyProofs) {
        return credentialJwtKeyProofs.stream()
            .map(keyProof -> Proof.builder()
                .proofType("jwt")
                .jwt(keyProof.serialize())
                .build())
            .toList();
    }
}
