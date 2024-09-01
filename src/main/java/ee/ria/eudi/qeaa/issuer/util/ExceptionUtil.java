package ee.ria.eudi.qeaa.issuer.util;

import lombok.experimental.UtilityClass;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.validation.method.ParameterValidationResult;
import org.springframework.web.method.annotation.HandlerMethodValidationException;

import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Collectors;

@UtilityClass
public class ExceptionUtil {

    public String getCauseMessages(Exception ex) {
        return ExceptionUtils.getThrowableList(ex).stream()
            .map(Throwable::getMessage)
            .filter(Objects::nonNull)
            .filter(Predicate.not(String::isBlank))
            .collect(Collectors.joining(" --> "));
    }

    public String getFirstValidationErrorMessage(HandlerMethodValidationException ex) {
        ParameterValidationResult firstValidationResult = ex.getAllValidationResults()
            .getFirst();
        String parameterName = firstValidationResult.getMethodParameter().getParameterName();
        String errorMessage = firstValidationResult
            .getResolvableErrors()
            .getFirst()
            .getDefaultMessage();
        return parameterName + ": " + errorMessage;
    }
}
