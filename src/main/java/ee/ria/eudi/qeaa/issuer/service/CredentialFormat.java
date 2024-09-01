package ee.ria.eudi.qeaa.issuer.service;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Arrays;

@Getter
@RequiredArgsConstructor
public enum CredentialFormat {
    MSO_MDOC("mso_mdoc"), VC_SD_JWT("vc+sd-jwt"), JWT_VC_JSON("jwt_vc_json"), JWT_VC_JSON_LD("jwt_vc_json-ld)"), LDP_VC("ldp_vc");

    private final String value;

    public static CredentialFormat fromValue(Object value) {
        return Arrays.stream(CredentialFormat.values())
            .filter(f -> f.getValue().equals(value))
            .findFirst()
            .orElse(null);
    }
}
