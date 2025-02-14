package ee.ria.eudi.qeaa.issuer.service;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public final class MobileDrivingLicence {
    private String administrativeNumber;
    private String familyName;
    private String familyNameNationalCharacter;
    private String givenName;
    private String givenNameNationalCharacter;
    private LocalDate birthDate;
    private String birthPlace;
    private LocalDate issueDate;
    private LocalDate expiryDate;
    private String issuingCountry;
    private String issuingAuthority;
    private String documentNumber;
    private byte[] portrait;
    private byte[] signatureUsualMark;
    private List<DrivingPrivilege> drivingPrivileges;
    private String unDistinguishingSign;
    private Boolean ageOver18;
}
