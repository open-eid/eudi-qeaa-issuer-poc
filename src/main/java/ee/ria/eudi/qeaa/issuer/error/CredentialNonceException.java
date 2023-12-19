package ee.ria.eudi.qeaa.issuer.error;

import lombok.Getter;

@Getter
public class CredentialNonceException extends ServiceException {
    public static final String ERROR_MESSAGE = "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce.";
    private final String cNonce;
    private final long cNonceExpiresIn;

    public CredentialNonceException(String cNonce, long cNonceExpiresIn) {
        super(ErrorCode.INVALID_PROOF, ERROR_MESSAGE);
        this.cNonce = cNonce;
        this.cNonceExpiresIn = cNonceExpiresIn;
    }
}
