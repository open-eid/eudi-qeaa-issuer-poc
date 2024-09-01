package ee.ria.eudi.qeaa.issuer.service;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum CredentialDoctype {
    ORG_ISO_18013_5_1_MDL("org.iso.18013.5.1.mDL");

    private final String uri;

    @JsonValue
    public String value() {
        return uri;
    }
}
