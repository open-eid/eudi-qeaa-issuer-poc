package ee.ria.eudi.qeaa.issuer.controller;

import ee.ria.eudi.qeaa.issuer.service.CredentialIssuerMetadata;
import ee.ria.eudi.qeaa.issuer.service.MetadataService;
import ee.ria.eudi.qeaa.issuer.util.RequestUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Locale;

@RestController
@RequiredArgsConstructor
public class MetadataController {
    public static final String WELL_KNOWN_OPENID_CREDENTIAL_ISSUER_REQUEST_MAPPING = "/.well-known/openid-credential-issuer";
    private final MetadataService metadataService;

    @GetMapping(path = WELL_KNOWN_OPENID_CREDENTIAL_ISSUER_REQUEST_MAPPING, produces = MediaType.APPLICATION_JSON_VALUE)
    public CredentialIssuerMetadata getMetadata(HttpServletRequest request) {
        List<Locale> locales = RequestUtil.getSupportedLocales(request);
        return metadataService.getMetadata(locales);
    }
}
