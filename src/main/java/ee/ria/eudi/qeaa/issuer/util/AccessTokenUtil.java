package ee.ria.eudi.qeaa.issuer.util;

import com.nimbusds.jose.util.Base64URL;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@UtilityClass
public class AccessTokenUtil {

    @SneakyThrows
    public String computeSHA256(String token) {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(token.getBytes(StandardCharsets.UTF_8));
        return Base64URL.encode(hash).toString();
    }
}
