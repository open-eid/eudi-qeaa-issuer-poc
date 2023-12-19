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
    private final Set<JWSAlgorithm> acceptedJWSAlgs;

    public JwsHeaderKeySelector(Set<JWSAlgorithm> acceptedJWSAlgs) {
        if (CollectionUtils.isEmpty(acceptedJWSAlgs)) {
            throw new IllegalArgumentException("Must specify at least one accepted JWS algorithm");
        }
        this.acceptedJWSAlgs = acceptedJWSAlgs;
    }

    @Override
    public List<Key> selectJWSKeys(final JWSHeader header, final SecurityContext context) throws KeySourceException {
        JWSAlgorithm alg = header.getAlgorithm();
        if (!acceptedJWSAlgs.contains(alg)) {
            throw new KeySourceException("JWS header algorithm not accepted: " + alg);
        }
        JWK jwk = header.getJWK();
        if (jwk == null) {
            throw new KeySourceException("Missing JWS jwk header parameter");
        }
        if (JWSAlgorithm.Family.RSA.contains(alg) && jwk instanceof RSAKey rsaKey) {
            try {
                return List.of(rsaKey.toRSAPublicKey());
            } catch (JOSEException e) {
                throw new KeySourceException("Invalid RSA JWK: " + e.getMessage(), e);
            }
        } else if (JWSAlgorithm.Family.EC.contains(alg) && jwk instanceof ECKey ecKey) {
            try {
                return List.of(ecKey.toECPublicKey());
            } catch (JOSEException e) {
                throw new KeySourceException("Invalid EC JWK: " + e.getMessage(), e);
            }
        } else {
            throw new KeySourceException("JWS header alg / jwk mismatch: alg=" + alg + " jwk.kty=" + jwk.getKeyType());
        }
    }
}
