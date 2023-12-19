package ee.ria.eudi.qeaa.issuer.validation;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import io.micrometer.common.util.StringUtils;

import java.text.ParseException;
import java.time.Clock;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class AccessTokenClaimsVerifier extends DefaultJWTClaimsVerifier<SecurityContext> {
    private final Clock systemClock;

    public AccessTokenClaimsVerifier(String issuer, String audience, long maxClockSkewSeconds, Clock systemClock) {
        super(new JWTClaimsSet.Builder()
                .claim(JWTClaimNames.ISSUER, issuer)
                .claim(JWTClaimNames.AUDIENCE, List.of(audience))
                .build(),
            Set.of(JWTClaimNames.SUBJECT, JWTClaimNames.ISSUED_AT, JWTClaimNames.EXPIRATION_TIME, "client_id", "cnf"));
        this.systemClock = systemClock;
        setMaxClockSkew((int) maxClockSkewSeconds);
    }

    @Override
    protected Date currentTime() {
        return Date.from(systemClock.instant());
    }

    @Override
    public void verify(JWTClaimsSet claimsSet, SecurityContext context) throws BadJWTException {
        super.verify(claimsSet, context);
        try {
            Map<String, Object> cnfClaim = claimsSet.getJSONObjectClaim("cnf");
            Object jkt = cnfClaim.get("jkt");
            if (StringUtils.isBlank((String) jkt)) {
                throw new BadJWTException("Invalid access token jkt claim");
            }
        } catch (ParseException e) {
            throw new BadJWTException("Invalid access token", e);
        }
    }
}
