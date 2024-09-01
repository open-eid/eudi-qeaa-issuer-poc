package ee.ria.eudi.qeaa.issuer.error;

import ee.ria.eudi.qeaa.issuer.util.ExceptionUtil;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.HandlerMethodValidationException;

import java.util.Map;

import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.SERVICE_EXCEPTION;

@Component
public class ErrorAttributes extends DefaultErrorAttributes {
    public static final String ERROR_ATTR_ERROR = "error";
    public static final String ERROR_ATTR_ERROR_DESCRIPTION = "error_description";
    public static final String C_NONCE = "c_nonce";
    public static final String C_NONCE_EXPIRES_IN = "c_nonce_expires_in";

    @Override
    public Map<String, Object> getErrorAttributes(WebRequest webRequest, ErrorAttributeOptions options) {
        Map<String, Object> attr = super.getErrorAttributes(webRequest, options);
        Throwable error = getError(webRequest);
        switch (error) {
            case CredentialNonceException ex -> {
                setCommonAttributes(attr, ex.getErrorCode(), ex.getMessage());
                attr.put(C_NONCE, ex.getCNonce());
                attr.put(C_NONCE_EXPIRES_IN, ex.getCNonceExpiresIn());
            }
            case ServiceException ex -> setCommonAttributes(attr, ex.getErrorCode(), ex.getMessage());
            case HandlerMethodValidationException ex ->
                setCommonAttributes(attr, INVALID_REQUEST, ExceptionUtil.getFirstValidationErrorMessage(ex));
            default -> setCommonAttributes(attr, SERVICE_EXCEPTION, error.getMessage());
        }
        return attr;
    }

    private void setCommonAttributes(Map<String, Object> attr, ErrorCode errorCode, String errorDescription) {
        attr.replace(ERROR_ATTR_ERROR, errorCode.name().toLowerCase());
        if (errorCode == SERVICE_EXCEPTION) {
            attr.put(ERROR_ATTR_ERROR_DESCRIPTION, "Internal server error");
        } else {
            attr.put(ERROR_ATTR_ERROR_DESCRIPTION, errorDescription);
        }
        attr.remove("message");
    }
}
