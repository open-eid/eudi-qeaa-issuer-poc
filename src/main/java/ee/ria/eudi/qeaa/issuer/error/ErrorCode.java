package ee.ria.eudi.qeaa.issuer.error;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {
    SERVICE_EXCEPTION(HttpStatus.INTERNAL_SERVER_ERROR),
    INVALID_REQUEST(HttpStatus.BAD_REQUEST),
    SUBJECT_NOT_FOUND(HttpStatus.BAD_REQUEST),

    /**
     * OpenID4VCI Credential request
     **/
    INVALID_CREDENTIAL_REQUEST(HttpStatus.BAD_REQUEST),
    UNSUPPORTED_CREDENTIAL_TYPE(HttpStatus.BAD_REQUEST),
    UNSUPPORTED_CREDENTIAL_FORMAT(HttpStatus.BAD_REQUEST),
    INVALID_PROOF(HttpStatus.BAD_REQUEST),
    INVALID_ENCRYPTION_PARAMETERS(HttpStatus.BAD_REQUEST),
    CREDENTIAL_REQUEST_DENIED(HttpStatus.BAD_REQUEST),
    /**
     * RFC 9449 Sender constrained access token
     **/
    INVALID_DPOP_PROOF(HttpStatus.UNAUTHORIZED),
    INVALID_TOKEN(HttpStatus.UNAUTHORIZED);

    private final HttpStatus httpStatus;
}
