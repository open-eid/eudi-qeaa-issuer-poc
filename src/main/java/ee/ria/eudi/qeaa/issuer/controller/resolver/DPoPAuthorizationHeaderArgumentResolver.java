package ee.ria.eudi.qeaa.issuer.controller.resolver;

import com.nimbusds.jwt.SignedJWT;
import ee.ria.eudi.qeaa.issuer.error.ServiceException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.text.ParseException;
import java.util.Enumeration;

import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.INVALID_TOKEN;

public class DPoPAuthorizationHeaderArgumentResolver implements HandlerMethodArgumentResolver {
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String DPOP_PREFIX = "DPoP ";

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.getParameterAnnotation(DPoPAuthorizationHeader.class) != null && SignedJWT.class.isAssignableFrom(parameter.getParameterType());
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
        HttpServletRequest request = (HttpServletRequest) webRequest.getNativeRequest();
        Enumeration<String> authHeaders = request.getHeaders(AUTHORIZATION_HEADER);
        if (!authHeaders.hasMoreElements()) {
            throw new ServiceException(INVALID_TOKEN, "Missing DPoP Authorization header");
        }
        String authorization = authHeaders.nextElement();
        if (authHeaders.hasMoreElements()) {
            throw new ServiceException(INVALID_TOKEN, "Duplicate DPoP Authorization header");
        }
        if (!authorization.startsWith(DPOP_PREFIX)) {
            throw new ServiceException(INVALID_TOKEN, "Invalid Authorization header type");
        }
        try {
            return SignedJWT.parse(authorization.replace(DPOP_PREFIX, ""));
        } catch (ParseException ex) {
            throw new ServiceException(INVALID_TOKEN, "Unable to parse DPoP Authorization header");
        }
    }
}
