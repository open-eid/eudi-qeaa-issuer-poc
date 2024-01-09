package ee.ria.eudi.qeaa.issuer.util;

import jakarta.servlet.http.HttpServletRequest;
import lombok.NonNull;
import lombok.experimental.UtilityClass;
import org.springframework.http.HttpHeaders;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;
import org.springframework.web.servlet.support.RequestContextUtils;

import java.util.List;
import java.util.Locale;

@UtilityClass
public class RequestUtil {

    public List<Locale> getSupportedLocales(@NonNull HttpServletRequest request) {
        if (RequestContextUtils.getLocaleResolver(request) instanceof AcceptHeaderLocaleResolver localeResolver) {
            if (request.getHeader(HttpHeaders.ACCEPT_LANGUAGE) == null) {
                return localeResolver.getSupportedLocales();
            } else {
                return List.of(localeResolver.resolveLocale(request));
            }
        }
        return List.of(request.getLocale());
    }
}
