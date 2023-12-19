package ee.ria.eudi.qeaa.issuer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

@TestConfiguration
public class IssuerTestConfiguration {

    @Bean
    public ECKey asSigningKey(SslBundles sslBundle) throws KeyStoreException, JOSEException {
        SslBundle bundle = sslBundle.getBundle("eudi-as");
        return ECKey.load(bundle.getStores().getKeyStore(), bundle.getKey().getAlias(), null);
    }

    @Bean
    public JWSAlgorithm asSigningKeyJwsAlg(ECKey asSigningKey) {
        return getJwsAlgorithm(asSigningKey.getCurve());
    }

    @Bean
    public ECKey walletSigningKey(SslBundles sslBundles) throws KeyStoreException, JOSEException {
        SslBundle bundle = sslBundles.getBundle("eudi-wallet");
        return ECKey.load(bundle.getStores().getKeyStore(), bundle.getKey().getAlias(), null);
    }

    @Bean
    public JWSAlgorithm walletSigningKeyJwsAlg(ECKey walletSigningKey) {
        return getJwsAlgorithm(walletSigningKey.getCurve());
    }

    @Bean
    public List<X509Certificate> issuerTrustedRootCAs(SslBundles sslBundles) throws KeyStoreException {
        SslBundle bundle = sslBundles.getBundle("eudi-issuer-ca");
        KeyStore trustStore = bundle.getStores().getTrustStore();
        List<X509Certificate> issuerTrustedRootCAs = new ArrayList<>();
        Enumeration<String> enumeration = trustStore.aliases();
        while (enumeration.hasMoreElements()) {
            String alias = enumeration.nextElement();
            if (trustStore.getCertificate(alias) instanceof X509Certificate x509Certificate) {
                issuerTrustedRootCAs.add(x509Certificate);
            }
        }
        return issuerTrustedRootCAs;
    }

    public JWSAlgorithm getJwsAlgorithm(Curve curve) {
        if (curve == Curve.P_256) {
            return JWSAlgorithm.ES256;
        } else if (curve == Curve.SECP256K1) {
            return JWSAlgorithm.ES256K;
        } else if (curve == Curve.P_384) {
            return JWSAlgorithm.ES384;
        } else if (curve == Curve.P_521) {
            return JWSAlgorithm.ES512;
        } else {
            throw new IllegalArgumentException("Unsupported curve");
        }
    }
}
