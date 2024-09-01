package ee.ria.eudi.qeaa.issuer.validation;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import ee.ria.eudi.qeaa.issuer.service.CredentialFormat;
import io.micrometer.common.util.StringUtils;

import java.text.ParseException;
import java.time.Clock;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static ee.ria.eudi.qeaa.issuer.service.MetadataService.DOCTYPE_ORG_ISO_18013_5_1_MDL;

public class AccessTokenClaimsVerifier extends DefaultJWTClaimsVerifier<SecurityContext> {
    public static final String TYPE_OPENID_CREDENTIAL = "openid_credential";
    private final Clock systemClock;

    public AccessTokenClaimsVerifier(String issuer, String audience, long maxClockSkewSeconds, Clock systemClock) {
        super(new JWTClaimsSet.Builder()
                .claim(JWTClaimNames.ISSUER, issuer)
                .claim(JWTClaimNames.AUDIENCE, List.of(audience))
                .build(),
            Set.of(JWTClaimNames.SUBJECT, JWTClaimNames.ISSUED_AT, JWTClaimNames.EXPIRATION_TIME, "client_id", "authorization_details", "cnf"));
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
        verifyAuthorizationDetailsList(claimsSet);
        verifyJwkConfirmationMethod(claimsSet);
    }

    private static void verifyAuthorizationDetailsList(JWTClaimsSet claimsSet) throws BadJWTException {
        try {
            List<Object> adClaims = claimsSet.getListClaim("authorization_details");
            if (adClaims == null || adClaims.isEmpty()) {
                throw new BadJWTException("Missing access token authorization_details claim");
            }
            for (Object item : adClaims) {
                if (item instanceof Map<?, ?> adClaim) {
                    verifyAuthorizationDetails(adClaim);
                } else {
                    throw new BadJWTException("Invalid access token authorization_details claim");
                }
            }
        } catch (ParseException e) {
            throw new BadJWTException("Parse exception", e);
        }
    }

    private static void verifyAuthorizationDetails(Map<?, ?> adClaim) throws BadJWTException {
        Object type = adClaim.get("type");
        if (!TYPE_OPENID_CREDENTIAL.equals(type)) {
            throw new BadJWTException("Invalid access token authorization_details.type claim");
        }
        Object configurationId = adClaim.get("credential_configuration_id");
        Object format = adClaim.get("format");
        Object doctype = adClaim.get("doctype");
        if (configurationId != null && (format != null || doctype != null)) {
            throw new BadJWTException("Invalid access token authorization_details.credential_configuration_id claim. Claims authorization_details.format and authorization_details.doctype must be null.");
        }
        if (configurationId == null) {
            CredentialFormat requestedFormat = CredentialFormat.fromValue(format);
            if (requestedFormat == null) {
                throw new BadJWTException("Invalid access token authorization_details.format claim");
            }
            if (CredentialFormat.MSO_MDOC == requestedFormat && !DOCTYPE_ORG_ISO_18013_5_1_MDL.equals(adClaim.get("doctype"))) {
                throw new BadJWTException("Invalid access token authorization_details.doctype claim");
            }
            if (CredentialFormat.VC_SD_JWT == requestedFormat && adClaim.get("vct") == null) {
                throw new BadJWTException("Missing access token authorization_details.vct claim");
            }
        }
    }

    private static void verifyJwkConfirmationMethod(JWTClaimsSet claimsSet) throws BadJWTException {
        try {
            Map<String, Object> cnfClaim = claimsSet.getJSONObjectClaim("cnf");
            Object jkt = cnfClaim.get("jkt");
            if (StringUtils.isBlank((String) jkt)) {
                throw new BadJWTException("Invalid access token jkt claim");
            }
        } catch (ParseException e) {
            throw new BadJWTException("Parse exception", e);
        }
    }
}
