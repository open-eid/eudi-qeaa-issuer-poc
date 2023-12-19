package ee.ria.eudi.qeaa.issuer.error;

import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;

import java.util.Map;

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
        if (error instanceof CredentialNonceException credentialNonceException) {
            setCommonAttributes(attr, credentialNonceException.getErrorCode(), credentialNonceException.getMessage());
            attr.put(C_NONCE, credentialNonceException.getCNonce());
            attr.put(C_NONCE_EXPIRES_IN, credentialNonceException.getCNonceExpiresIn());
        } else if (error instanceof ServiceException serviceException) {
            setCommonAttributes(attr, serviceException.getErrorCode(), serviceException.getMessage());
        } else {
            setCommonAttributes(attr, ErrorCode.SERVICE_EXCEPTION, error.getMessage());
        }
        return attr;
    }

    private void setCommonAttributes(Map<String, Object> attr, ErrorCode errorCode, String errorDescription) {
        attr.replace(ERROR_ATTR_ERROR, errorCode.name().toLowerCase());
        attr.put(ERROR_ATTR_ERROR_DESCRIPTION, errorDescription);
        attr.remove("message");
    }
}
