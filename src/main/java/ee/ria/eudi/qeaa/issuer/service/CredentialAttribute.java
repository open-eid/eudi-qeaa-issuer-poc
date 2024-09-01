package ee.ria.eudi.qeaa.issuer.service;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum CredentialAttribute {
    ORG_ISO_18013_5_1_FAMILY_NAME(CredentialDoctype.ORG_ISO_18013_5_1_MDL, CredentialNamespace.ORG_ISO_18013_5_1, "family_name", true),
    ORG_ISO_18013_5_1_GIVEN_NAME(CredentialDoctype.ORG_ISO_18013_5_1_MDL, CredentialNamespace.ORG_ISO_18013_5_1, "given_name", true),
    ORG_ISO_18013_5_1_BIRTH_DATE(CredentialDoctype.ORG_ISO_18013_5_1_MDL, CredentialNamespace.ORG_ISO_18013_5_1, "birth_date", true),
    ORG_ISO_18013_5_1_ISSUE_DATE(CredentialDoctype.ORG_ISO_18013_5_1_MDL, CredentialNamespace.ORG_ISO_18013_5_1, "issue_date", true),
    ORG_ISO_18013_5_1_EXPIRY_DATE(CredentialDoctype.ORG_ISO_18013_5_1_MDL, CredentialNamespace.ORG_ISO_18013_5_1, "expiry_date", true),
    ORG_ISO_18013_5_1_ISSUING_COUNTRY(CredentialDoctype.ORG_ISO_18013_5_1_MDL, CredentialNamespace.ORG_ISO_18013_5_1, "issuing_country", true),
    ORG_ISO_18013_5_1_ISSUING_AUTHORITY(CredentialDoctype.ORG_ISO_18013_5_1_MDL, CredentialNamespace.ORG_ISO_18013_5_1, "issuing_authority", true),
    ORG_ISO_18013_5_1_DOCUMENT_NUMBER(CredentialDoctype.ORG_ISO_18013_5_1_MDL, CredentialNamespace.ORG_ISO_18013_5_1, "document_number", true),
    ORG_ISO_18013_5_1_PORTRAIT(CredentialDoctype.ORG_ISO_18013_5_1_MDL, CredentialNamespace.ORG_ISO_18013_5_1, "portrait", true),
    ORG_ISO_18013_5_1_DRIVING_PRIVILEGES(CredentialDoctype.ORG_ISO_18013_5_1_MDL, CredentialNamespace.ORG_ISO_18013_5_1, "driving_privileges", true),
    ORG_ISO_18013_5_1_UN_DISTINGUISHING_SIGN(CredentialDoctype.ORG_ISO_18013_5_1_MDL, CredentialNamespace.ORG_ISO_18013_5_1, "un_distinguishing_sign", true);

    private final CredentialDoctype doctype;
    private final CredentialNamespace namespace;
    private final String uri;
    private final boolean mandatory;
}
