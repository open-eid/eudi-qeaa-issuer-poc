package ee.ria.eudi.qeaa.issuer.validation;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.util.DateUtils;
import ee.ria.eudi.qeaa.issuer.error.CredentialNonceException;
import ee.ria.eudi.qeaa.issuer.error.ServiceException;
import ee.ria.eudi.qeaa.issuer.model.CredentialNonce;

import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.INVALID_PROOF;

public class JwtKeyProofClaimsVerifier extends DefaultJWTClaimsVerifier<SecurityContext> {
    private final long expiryTimeSeconds;
    private final long maxClockSkewSeconds;
    private final CredentialNonce cNonce;
    private final Clock systemClock;

    public JwtKeyProofClaimsVerifier(String issuer,
                                     String audience,
                                     CredentialNonce cNonce,
                                     long expiryTimeSeconds,
                                     long maxClockSkewSeconds,
                                     Clock systemClock) {
        super(new JWTClaimsSet.Builder()
                .claim("iss", issuer)
                .claim("aud", List.of(audience))
                .build(),
            Set.of(JWTClaimNames.ISSUED_AT));
        this.expiryTimeSeconds = expiryTimeSeconds;
        this.maxClockSkewSeconds = maxClockSkewSeconds;
        this.cNonce = cNonce;
        this.systemClock = systemClock;
    }

    @Override
    public void verify(JWTClaimsSet claimsSet, SecurityContext context) throws BadJWTException {
        super.verify(claimsSet, context);

        Date currentTime = Date.from(systemClock.instant());
        if (!DateUtils.isAfter(claimsSet.getIssueTime(), currentTime, expiryTimeSeconds + maxClockSkewSeconds)) {
            throw new ServiceException(INVALID_PROOF, "Key Proof expired");
        }
        if (!DateUtils.isBefore(claimsSet.getIssueTime(), currentTime, maxClockSkewSeconds)) {
            throw new ServiceException(INVALID_PROOF, "Key Proof not yet valid");
        }
        Object nonce = claimsSet.getClaim("nonce");
        long cNonceExpiryTime = Instant.now().getEpochSecond() - cNonce.getIssuedAt().getEpochSecond();
        if (!cNonce.getNonce().equals(nonce)) {
            throw new CredentialNonceException(cNonce.getNonce(), cNonceExpiryTime);
        }
    }
}
