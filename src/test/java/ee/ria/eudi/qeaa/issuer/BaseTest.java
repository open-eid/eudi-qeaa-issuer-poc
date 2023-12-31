package ee.ria.eudi.qeaa.issuer;

import COSE.AlgorithmID;
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
import ee.ria.eudi.qeaa.issuer.configuration.properties.IssuerProperties;
import ee.ria.eudi.qeaa.issuer.model.CredentialNonce;
import ee.ria.eudi.qeaa.issuer.model.CredentialRequest;
import ee.ria.eudi.qeaa.issuer.model.CredentialResponse;
import ee.ria.eudi.qeaa.issuer.repository.CredentialNonceRepository;
import id.walt.mdoc.COSECryptoProviderKeyInfo;
import id.walt.mdoc.SimpleCOSECryptoProvider;
import id.walt.mdoc.cose.COSESign1;
import id.walt.mdoc.dataelement.StringElement;
import id.walt.mdoc.doc.MDoc;
import id.walt.mdoc.issuersigned.IssuerSigned;
import id.walt.mdoc.issuersigned.IssuerSignedItem;
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
import org.springframework.boot.test.context.SpringBootTest;
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
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.NAMESPACE_ORG_ISO_18013_5_1;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.BIRTH_DATE;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.DOCUMENT_NUMBER;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.DRIVING_PRIVILEGES;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.EXPIRY_DATE;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.FAMILY_NAME;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.GIVEN_NAME;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.ISSUE_DATE;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.ISSUING_AUTHORITY;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.ISSUING_COUNTRY;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.PORTRAIT;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.UN_DISTINGUISHING_SIGN;
import static io.restassured.config.RedirectConfig.redirectConfig;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@SpringBootTest(webEnvironment = RANDOM_PORT)
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

    protected void assertCNonce(CredentialResponse response, String accessTokenHash, CredentialNonce cNonce) {
        CredentialNonce newCNonce = credentialNonceRepository.findByAccessTokenHash(accessTokenHash);
        assertThat(response.cNonce(), notNullValue());
        assertThat(response.cNonceExpiresIn(), notNullValue());
        assertThat(newCNonce, notNullValue());
        assertThat(newCNonce.getNonce(), notNullValue());
        assertThat(newCNonce.getNonce(), not(equalTo(cNonce.getNonce())));
        assertThat(newCNonce.getNonce(), equalTo(response.cNonce()));
        assertThat(newCNonce.getIssuedAt(), notNullValue());
        assertThat(newCNonce.getIssuedAt(), greaterThan(cNonce.getIssuedAt()));
    }

    protected void assertMsoMDoc(MDoc mDoc) {
        assertThat(mDoc.verifyDocType(), is(true));
        assertThat(mDoc.verifyValidity(), is(true));
        assertThat(mDoc.verifyIssuerSignedItems(), is(true));
        SimpleCOSECryptoProvider issuerCryptoProvider = getIssuerCryptoProvider(mDoc);
        assertThat(mDoc.verifyCertificate(issuerCryptoProvider, KEY_ID_ISSUER), is(true));
        assertThat(mDoc.verifySignature(issuerCryptoProvider, KEY_ID_ISSUER), is(true));
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
        List<IssuerSignedItem> issuerSignedItems = mDoc.getIssuerSignedItems(NAMESPACE_ORG_ISO_18013_5_1);
        Map<String, Object> claims = issuerSignedItems.stream()
            .collect(Collectors.toMap(i -> i.getElementIdentifier().getValue(), i -> i.getElementValue().getValue()));

        assertThat(claims.get(FAMILY_NAME.toString()), is("Männik"));
        assertThat(claims.get(GIVEN_NAME.toString()), is("Mari-Liis"));
        assertThat(claims.get(BIRTH_DATE.toString()), is(LocalDate.Companion.parse("1979-12-24")));
        assertThat(claims.get(ISSUE_DATE.toString()), is(LocalDate.Companion.parse("2020-12-30")));
        assertThat(claims.get(EXPIRY_DATE.toString()), is(LocalDate.Companion.parse("2028-12-30")));
        assertThat(claims.get(ISSUING_COUNTRY.toString()), is("EE"));
        assertThat(claims.get(ISSUING_AUTHORITY.toString()), is("ARK"));
        assertThat(claims.get(DOCUMENT_NUMBER.toString()), is("ET000000"));
        assertThat((List<String>) claims.get(DRIVING_PRIVILEGES.toString()), Matchers.containsInRelativeOrder(new StringElement("A"), new StringElement("B")));
        assertThat(claims.get(UN_DISTINGUISHING_SIGN.toString()), is("EST"));
        assertThat(claims.get(PORTRAIT.toString()), is(Hex.decode(subjectPortrait.getContentAsString(StandardCharsets.UTF_8))));
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
            .type(JOSEObjectType.JWT)
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
            .claim("client_id", WALLET_CLIENT_ID);
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

    protected SignedJWT getJwtKeyProof(String cNonce) throws JOSEException {
        return getJwtKeyProof(getJwtKeyProofClaims(cNonce));
    }

    protected SignedJWT getJwtKeyProof(JWTClaimsSet claimsSet) throws JOSEException {
        SignedJWT jwtKeyProof = new SignedJWT(new JWSHeader.Builder(walletSigningKeyJwsAlg)
            .type(new JOSEObjectType("openid4vci-proof+jwt"))
            .jwk(walletSigningKey.toPublicJWK())
            .build(), claimsSet);
        jwtKeyProof.sign(new ECDSASigner(walletSigningKey));
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
        CredentialRequest.Proof proof = CredentialRequest.Proof.builder()
            .proofType("jwt")
            .jwt(credentialJwtKeyProof.serialize())
            .build();
        return CredentialRequest.builder()
            .format("mso_mdoc")
            .doctype("org.iso.18013.5.1.mDL")
            .proof(proof)
            .build();
    }
}
