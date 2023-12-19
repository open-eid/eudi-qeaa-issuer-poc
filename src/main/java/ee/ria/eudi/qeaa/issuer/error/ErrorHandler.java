package ee.ria.eudi.qeaa.issuer.error;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.io.IOException;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Collectors;

@Slf4j
@ControllerAdvice
@RequiredArgsConstructor
public class ErrorHandler {

    @ExceptionHandler({ServiceException.class})
    public void handleServiceException(ServiceException ex, HttpServletResponse response) throws IOException {
        if (ex.getCause() == null) {
            StackTraceElement stackElem = ex.getStackTrace()[0];
            log.error("Service exception: {} - {}:LN{}", ex.getMessage(), stackElem.getClassName(), stackElem.getLineNumber());
        } else {
            log.error("Service exception: {}", getCauseMessages(ex), ex);
        }
        if (ex.getErrorCode().getHttpStatus() == HttpStatus.UNAUTHORIZED) {
            response.addHeader("WWW-Authenticate", "DPoP algs=\"ES256\" error=\"%s\" error_description=\"%s\""
                .formatted(ex.getErrorCode().name().toLowerCase(), ex.getMessage()));
        }
        response.sendError(ex.getErrorCode().getHttpStatus().value());
    }

    @ExceptionHandler({Exception.class})
    public void handleAll(Exception ex, HttpServletResponse response) throws IOException {
        log.error("Unexpected exception: {}", getCauseMessages(ex), ex);
        response.sendError(HttpStatus.INTERNAL_SERVER_ERROR.value());
    }

    public String getCauseMessages(Exception ex) {
        return ExceptionUtils.getThrowableList(ex).stream()
            .map(Throwable::getMessage)
            .filter(Objects::nonNull)
            .filter(Predicate.not(String::isBlank))
            .collect(Collectors.joining(" --> "));
    }
}
