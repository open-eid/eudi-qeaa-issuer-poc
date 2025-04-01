package ee.ria.eudi.qeaa.issuer.configuration;

import id.walt.mdoc.COSECryptoProviderKeyInfo;
import id.walt.mdoc.SimpleCOSECryptoProvider;
import org.cose.java.AlgorithmID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.List;

@Configuration
public class MDocConfiguration {
    public static final String KEY_ID_ISSUER = "issuer-key-id";

    @Bean
    public SimpleCOSECryptoProvider issuerCryptoProvider(KeyPair issuerKey, List<X509Certificate> issuerCertificateChain) {
        PublicKey publicKey = issuerKey.getPublic();
        if (publicKey instanceof ECPublicKey ecPublicKey) {
            return new SimpleCOSECryptoProvider(List.of(new COSECryptoProviderKeyInfo(KEY_ID_ISSUER, getAlgorithmId(ecPublicKey),
                publicKey, issuerKey.getPrivate(), issuerCertificateChain, Collections.emptyList())));
        } else {
            throw new IllegalArgumentException("Invalid key type. An Elliptic Curve key is required by ISO/IEC 18013-5:2021.");
        }
    }

    private AlgorithmID getAlgorithmId(ECPublicKey ecPublicKey) {
        int bitLength = ecPublicKey.getParams().getOrder().bitLength();
        return switch (bitLength) {
            case 256 -> AlgorithmID.ECDSA_256;
            case 384 -> AlgorithmID.ECDSA_384;
            case 521 -> AlgorithmID.ECDSA_512;
            default -> throw new IllegalArgumentException("Unsupported key size: " + bitLength);
        };
    }
}
