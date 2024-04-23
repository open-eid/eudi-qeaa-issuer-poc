package ee.ria.eudi.qeaa.issuer.service;

import ee.ria.eudi.qeaa.issuer.configuration.properties.IssuerProperties;
import ee.ria.eudi.qeaa.issuer.model.CredentialAttribute;
import ee.ria.eudi.qeaa.issuer.model.CredentialIssuerMetadata;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

import static ee.ria.eudi.qeaa.issuer.controller.CredentialController.CREDENTIAL_REQUEST_MAPPING;
import static ee.ria.eudi.qeaa.issuer.controller.CredentialNonceController.CREDENTIAL_NONCE_REQUEST_MAPPING;
import static ee.ria.eudi.qeaa.issuer.model.CredentialIssuerMetadata.CredentialType.Claim;
import static ee.ria.eudi.qeaa.issuer.model.CredentialIssuerMetadata.CredentialType.Display;
import static ee.ria.eudi.qeaa.issuer.model.CredentialIssuerMetadata.CredentialType.ProofType;

@Service
@RequiredArgsConstructor
public class MetadataService {
    private final IssuerProperties issuerProperties;
    private final MessageSource messageSource;
    private final X509Certificate issuerCert;

    @Cacheable("metadata")
    public CredentialIssuerMetadata getMetadata(List<Locale> locales) {
        return CredentialIssuerMetadata.builder()
            .credentialIssuer(issuerProperties.issuer().baseUrl())
            .credentialEndpoint(issuerProperties.issuer().baseUrl() + CREDENTIAL_REQUEST_MAPPING)
            .credentialNonceEndpoint(issuerProperties.issuer().baseUrl() + CREDENTIAL_NONCE_REQUEST_MAPPING)
            .display(getCredentialIssuerDisplayObjects(locales))
            .credentialConfigurationsSupported(getSupportedCredentialConfigurations(locales))
            .authorizationServers(List.of(issuerProperties.as().baseUrl()))
            .build();
    }

    private Map<String, CredentialIssuerMetadata.CredentialType> getSupportedCredentialConfigurations(List<Locale> locales) {
        return Map.of("org.iso.18013.5.1.mDL", CredentialIssuerMetadata.CredentialType.builder()
            .format("mso_mdoc")
            .doctype("org.iso.18013.5.1.mDL")
            .cryptographicBindingMethodsSupported(List.of("cose_key"))
            .credentialSigningAlgValuesSupported(List.of(getSupportedSigningAlg()))
            .proofTypesSupported(getSupportedProofTypes())
            .display(getCredentialTypeDisplayObjects(locales))
            .claims(getSupportedClaims(locales))
            .build());
    }

    private String getSupportedSigningAlg() {
        if (issuerCert.getPublicKey() instanceof ECPublicKey ecPublicKey) {
            int bitLength = ecPublicKey.getParams().getOrder().bitLength();
            return switch (bitLength) {
                case 256 -> "ES256";
                case 384 -> "ES384";
                case 521 -> "ES512";
                default -> throw new IllegalArgumentException("Unsupported key size: " + bitLength);
            };
        } else if (issuerCert.getPublicKey() instanceof RSAPublicKey rsaPublicKey) {
            int bitLength = rsaPublicKey.getModulus().bitLength();
            return switch (bitLength) {
                case 2048 -> "RS256";
                case 3072 -> "RS384";
                case 4096 -> "RS512";
                default -> throw new IllegalArgumentException("Unsupported key size: " + bitLength);
            };
        } else {
            throw new IllegalArgumentException("Unsupported key");
        }
    }

    private Map<String, ProofType> getSupportedProofTypes() {
        return Map.of("jwt", ProofType.builder().proofSigningAlgValuesSupported(List.of(
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512"
        )).build());
    }

    private List<CredentialIssuerMetadata.Display> getCredentialIssuerDisplayObjects(List<Locale> locales) {
        return locales.stream().map(locale -> CredentialIssuerMetadata.Display.builder()
            .name(messageSource.getMessage("metadata.issuer.name", null, locale))
            .locale(locale.getLanguage())
            .build()).toList();
    }

    private List<Display> getCredentialTypeDisplayObjects(List<Locale> locales) {
        return locales.stream().map(locale -> Display.builder()
            .name(messageSource.getMessage("metadata.issuer.credential.name", null, locale))
            .logo(Display.Logo.builder().uri(messageSource.getMessage("metadata.issuer.credential.logo", null, locale)).build())
            .description(messageSource.getMessage("metadata.issuer.credential.description", null, locale))
            .textColor(messageSource.getMessage("metadata.issuer.credential.text-color", null, locale))
            .backgroundColor(messageSource.getMessage("metadata.issuer.credential.background-color", null, locale))
            .locale(locale.getLanguage())
            .build()).toList();
    }

    private Map<String, Map<String, Claim>> getSupportedClaims(List<Locale> locales) {
        return Arrays.stream(CredentialAttribute.values())
            .collect(Collectors.groupingBy(credentialAttribute -> credentialAttribute.getNamespace().getUri(),
                Collectors.toMap(CredentialAttribute::getUri, attr -> Claim.builder()
                    .mandatory(attr.isMandatory())
                    .display(getClaimDisplayObjects(attr, locales))
                    .build()
                )
            ));
    }

    private List<Claim.Display> getClaimDisplayObjects(CredentialAttribute attribute, List<Locale> locales) {
        return locales.stream().map(locale -> Claim.Display.builder()
            .name(messageSource.getMessage(attribute.getNamespace().getUri() + "." + attribute.getUri(), null, locale))
            .locale(locale.getLanguage())
            .build()).toList();
    }
}
