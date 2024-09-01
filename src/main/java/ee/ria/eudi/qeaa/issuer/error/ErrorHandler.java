package ee.ria.eudi.qeaa.issuer.error;

import ee.ria.eudi.qeaa.issuer.util.ExceptionUtil;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;

import java.io.IOException;

@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
public class ErrorHandler {

    @ExceptionHandler({ServiceException.class})
    public void handleServiceException(ServiceException ex, HttpServletResponse response) throws IOException {
        if (ex.getCause() == null) {
            StackTraceElement stackElem = ex.getStackTrace()[0];
            log.error("Service exception: {} - {}:LN{}", ex.getMessage(), stackElem.getClassName(), stackElem.getLineNumber());
        } else {
            log.error("Service exception: {}", ExceptionUtil.getCauseMessages(ex), ex);
        }
        if (ex.getErrorCode().getHttpStatus() == HttpStatus.UNAUTHORIZED) {
            response.addHeader("WWW-Authenticate", "DPoP algs=\"ES256\" error=\"%s\" error_description=\"%s\""
                .formatted(ex.getErrorCode().name().toLowerCase(), ex.getMessage()));
        }
        response.sendError(ex.getErrorCode().getHttpStatus().value());
    }

    @ExceptionHandler({HandlerMethodValidationException.class})
    public void handleBindException(HandlerMethodValidationException ex, HttpServletResponse response) throws IOException {
        log.error("User input exception: {}", ex.getMethod().getName() + " -> " + ExceptionUtil.getFirstValidationErrorMessage(ex));
        response.sendError(400);
    }

    @ExceptionHandler({Exception.class})
    public void handleAll(Exception ex, HttpServletResponse response) throws IOException {
        log.error("Unexpected exception: {}", ExceptionUtil.getCauseMessages(ex), ex);
        response.sendError(HttpStatus.INTERNAL_SERVER_ERROR.value());
    }
}
