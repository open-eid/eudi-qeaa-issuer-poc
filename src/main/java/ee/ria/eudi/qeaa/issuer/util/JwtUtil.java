package ee.ria.eudi.qeaa.issuer.util;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import ee.ria.eudi.qeaa.issuer.error.ServiceException;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;

import java.security.PublicKey;

import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.SERVICE_EXCEPTION;

@UtilityClass
public class JwtUtil {

    @SneakyThrows
    public PublicKey toPublicKey(JWK jwk) {
        if (jwk.getKeyType() == KeyType.EC) {
            return jwk.toECKey().toPublicKey();
        } else if (jwk.getKeyType() == KeyType.RSA) {
            return jwk.toRSAKey().toPublicKey();
        } else {
            throw new ServiceException(SERVICE_EXCEPTION, "Unsupported key type");
        }
    }
}
