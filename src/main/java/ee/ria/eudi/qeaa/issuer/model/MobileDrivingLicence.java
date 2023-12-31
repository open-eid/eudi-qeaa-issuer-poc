package ee.ria.eudi.qeaa.issuer.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

import java.time.LocalDate;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public final class MobileDrivingLicence {
    public static final String DOC_TYPE_ORG_ISO_18013_5_1_MDL = "org.iso.18013.5.1.mDL";
    public static final String NAMESPACE_ORG_ISO_18013_5_1 = "org.iso.18013.5.1";

    private String familyName;
    private String givenName;
    private LocalDate birthDate;
    private LocalDate issueDate;
    private LocalDate expiryDate;
    private String issuingCountry;
    private String issuingAuthority;
    private String documentNumber;
    private byte[] portrait;
    private List<String> drivingPrivileges;
    private String unDistinguishingSign;

    @Getter
    @RequiredArgsConstructor
    public enum SupportedClaims {
        FAMILY_NAME,
        GIVEN_NAME,
        BIRTH_DATE,
        ISSUE_DATE,
        EXPIRY_DATE,
        ISSUING_COUNTRY,
        ISSUING_AUTHORITY,
        DOCUMENT_NUMBER,
        PORTRAIT,
        DRIVING_PRIVILEGES,
        UN_DISTINGUISHING_SIGN;

        private final boolean mandatory;

        SupportedClaims() {
            this.mandatory = true;
        }

        @Override
        public String toString() {
            return super.toString().toLowerCase();
        }
    }
}
