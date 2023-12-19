package ee.ria.eudi.qeaa.issuer.util;

import com.nimbusds.jose.util.Base64URL;
import ee.ria.eudi.qeaa.issuer.error.ServiceException;
import lombok.experimental.UtilityClass;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@UtilityClass
public class AccessTokenUtil {

    public String computeSHA256(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64URL.encode(hash).toString();
        } catch (NoSuchAlgorithmException e) {
            throw new ServiceException(e);
        }
    }
}
