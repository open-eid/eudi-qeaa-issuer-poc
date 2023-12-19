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

import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.INVALID_DPOP_PROOF;

public class DPoPHeaderArgumentResolver implements HandlerMethodArgumentResolver {

    public static final String DPOP_HEADER = "DPoP";

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.getParameterAnnotation(DPoPHeader.class) != null && SignedJWT.class.isAssignableFrom(parameter.getParameterType());
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
        HttpServletRequest request = (HttpServletRequest) webRequest.getNativeRequest();
        Enumeration<String> dPoPHeaders = request.getHeaders(DPOP_HEADER);
        if (!dPoPHeaders.hasMoreElements()) {
            throw new ServiceException(INVALID_DPOP_PROOF, "Missing DPoP header");
        }
        String dPoPHeader = dPoPHeaders.nextElement();
        if (dPoPHeaders.hasMoreElements()) {
            throw new ServiceException(INVALID_DPOP_PROOF, "Duplicate DPoP header");
        }
        try {
            return SignedJWT.parse(dPoPHeader);
        } catch (ParseException ex) {
            throw new ServiceException(INVALID_DPOP_PROOF, "Unable to parse DPoP header");
        }
    }
}
