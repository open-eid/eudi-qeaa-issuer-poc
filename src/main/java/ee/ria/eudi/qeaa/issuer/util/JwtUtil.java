package ee.ria.eudi.qeaa.issuer.util;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.eudi.qeaa.issuer.error.ServiceException;
import lombok.experimental.UtilityClass;

import java.security.PublicKey;
import java.text.ParseException;
import java.util.Map;

import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.INVALID_ENCRYPTION_PARAMETERS;
import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.SERVICE_EXCEPTION;

@UtilityClass
public class JwtUtil {

    public PublicKey toPublicKey(JWK jwk) throws JOSEException {
        if (jwk.getKeyType() == KeyType.EC) {
            return jwk.toECKey().toPublicKey();
        } else if (jwk.getKeyType() == KeyType.RSA) {
            return jwk.toRSAKey().toPublicKey();
        } else {
            throw new ServiceException(SERVICE_EXCEPTION, "Unsupported key type");
        }
    }

    public String getEncryptedJWT(String jwk, String alg, String enc, Map<String, Object> claims) {
        try {
            JWK key = JWK.parse(jwk);
            JWEAlgorithm jweAlg = JWEAlgorithm.parse(alg);
            EncryptionMethod jweEnc = EncryptionMethod.parse(enc);
            JWEHeader header = new JWEHeader.Builder(jweAlg, jweEnc).type(JOSEObjectType.JWT).build();
            EncryptedJWT encryptedJWT = new EncryptedJWT(header, JWTClaimsSet.parse(claims));
            encryptedJWT.encrypt(JwtUtil.getJWEEncrypter(key));
            return encryptedJWT.serialize();
        } catch (ParseException e) {
            throw new ServiceException(INVALID_ENCRYPTION_PARAMETERS, "Invalid credential response encryption key", e);
        } catch (JOSEException e) {
            throw new ServiceException(e);
        }
    }

    public JWEEncrypter getJWEEncrypter(JWK jwk) throws JOSEException {
        if (jwk.getKeyType() == KeyType.RSA) {
            return new RSAEncrypter(jwk.toRSAKey());
        } else if (jwk.getKeyType() == KeyType.EC) {
            return new ECDHEncrypter(jwk.toECKey());
        } else {
            throw new ServiceException(INVALID_ENCRYPTION_PARAMETERS, "Invalid credential response encryption key type: " + jwk.getKeyType());
        }
    }
}
