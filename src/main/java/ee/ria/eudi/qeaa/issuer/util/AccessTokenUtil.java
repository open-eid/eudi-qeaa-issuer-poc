package ee.ria.eudi.qeaa.issuer.util;

import com.nimbusds.jose.util.Base64URL;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Utility class for computing SHA-256 hash of the access token.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9449.html#section-4.2">RFC 9449, section-4.2</a>
 */
@UtilityClass
public class AccessTokenUtil {

    @SneakyThrows
    public String computeSHA256(String token) {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(token.getBytes(StandardCharsets.US_ASCII));
        return Base64URL.encode(hash).toString();
    }
}
