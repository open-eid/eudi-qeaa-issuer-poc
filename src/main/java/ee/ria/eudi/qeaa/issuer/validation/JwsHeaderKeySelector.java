package ee.ria.eudi.qeaa.issuer.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;

import java.security.Key;
import java.util.List;
import java.util.Set;

public class JwsHeaderKeySelector implements JWSKeySelector<SecurityContext> {
    private final Set<JWSAlgorithm> acceptedJWSAlgorithms;

    public JwsHeaderKeySelector(Set<JWSAlgorithm> acceptedJWSAlgorithms) {
        if (CollectionUtils.isEmpty(acceptedJWSAlgorithms)) {
            throw new IllegalArgumentException("Must specify at least one accepted JWS algorithm");
        }
        this.acceptedJWSAlgorithms = acceptedJWSAlgorithms;
    }

    @Override
    public List<Key> selectJWSKeys(final JWSHeader header, final SecurityContext context) throws KeySourceException {
        JWSAlgorithm alg = header.getAlgorithm();
        if (!acceptedJWSAlgorithms.contains(alg)) {
            throw new KeySourceException("JWS header algorithm not accepted: " + alg);
        }
        JWK jwk = header.getJWK();
        switch (jwk) {
            case null -> throw new KeySourceException("Missing JWS jwk header parameter");
            case RSAKey rsaKey when JWSAlgorithm.Family.RSA.contains(alg) -> {
                try {
                    return List.of(rsaKey.toRSAPublicKey());
                } catch (JOSEException e) {
                    throw new KeySourceException("Invalid RSA JWK: " + e.getMessage(), e);
                }
            }
            case ECKey ecKey when JWSAlgorithm.Family.EC.contains(alg) -> {
                try {
                    return List.of(ecKey.toECPublicKey());
                } catch (JOSEException e) {
                    throw new KeySourceException("Invalid EC JWK: " + e.getMessage(), e);
                }
            }
            default ->
                throw new KeySourceException("JWS header alg / jwk mismatch: alg=" + alg + " jwk.kty=" + jwk.getKeyType());
        }
    }
}
