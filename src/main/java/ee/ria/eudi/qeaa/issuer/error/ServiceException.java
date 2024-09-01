package ee.ria.eudi.qeaa.issuer.error;

import lombok.Getter;

@Getter
public class ServiceException extends RuntimeException {
    private final ErrorCode errorCode;

    public ServiceException(String message) {
        super(message);
        this.errorCode = ErrorCode.SERVICE_EXCEPTION;
    }

    public ServiceException(Throwable cause) {
        super(cause);
        this.errorCode = ErrorCode.SERVICE_EXCEPTION;
    }

    public ServiceException(ErrorCode errorCode, Throwable cause) {
        super(cause);
        this.errorCode = errorCode;
    }

    public ServiceException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public ServiceException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }
}
