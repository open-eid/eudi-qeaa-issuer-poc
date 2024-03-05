package ee.ria.eudi.qeaa.issuer.model;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum CredentialNamespace {
    ORG_ISO_18013_5_1("org.iso.18013.5.1"),
    ORG_ISO_18013_5_1_EE("org.iso.18013.5.1.EE");

    private final String uri;

    @JsonValue
    public String value() {
        return uri;
    }
}
