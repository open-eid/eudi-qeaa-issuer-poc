package ee.ria.eudi.qeaa.issuer.service;

import ee.ria.eudi.qeaa.issuer.error.ServiceException;
import id.walt.mdoc.dataelement.BooleanElement;
import id.walt.mdoc.dataelement.ByteStringElement;
import id.walt.mdoc.dataelement.DEFullDateMode;
import id.walt.mdoc.dataelement.DataElement;
import id.walt.mdoc.dataelement.FullDateElement;
import id.walt.mdoc.dataelement.ListElement;
import id.walt.mdoc.dataelement.MapElement;
import id.walt.mdoc.dataelement.MapKey;
import id.walt.mdoc.dataelement.StringElement;
import kotlinx.datetime.LocalDate;
import lombok.RequiredArgsConstructor;
import org.modelmapper.TypeMap;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static ee.ria.eudi.qeaa.issuer.error.ErrorCode.UNSUPPORTED_CREDENTIAL_FORMAT;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_ADMINISTRATIVE_NUMBER;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_AGE_OVER_18;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_BIRTH_DATE;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_BIRTH_PLACE;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_DOCUMENT_NUMBER;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_DRIVING_PRIVILEGES;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_EXPIRY_DATE;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_FAMILY_NAME;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_FAMILY_NAME_NATIONAL_CHARACTER;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_GIVEN_NAME;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_GIVEN_NAME_NATIONAL_CHARACTER;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_ISSUE_DATE;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_ISSUING_AUTHORITY;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_ISSUING_COUNTRY;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_PORTRAIT;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_SIGNATURE_USUAL_MARK;
import static ee.ria.eudi.qeaa.issuer.service.CredentialAttribute.ORG_ISO_18013_5_1_UN_DISTINGUISHING_SIGN;

/**
 * The CredentialService class provides an abstraction layer for generating credentials in various formats.
 * This service is designed to be extensible, allowing integrators to modify or extend the functionality to support
 * additional credential formats as needed. The current implementation supports the generation of ISO/IEC 18013-5:2021
 * Mobile Driving Licences in the MDoc format.
 * <p>
 * The use of generics and a TypeMap from ModelMapper enables the service to map subject claims from different data sources
 * into a standardized Mobile Driving Licence model. This approach provides flexibility for integrator in handling
 * various input data structures while maintaining a consistent output format for credentials.
 */
@Service
@RequiredArgsConstructor
public class CredentialService {
    private final MDocService mDocService;

    public <T> String getMobileDrivingLicence(CredentialFormat credentialFormat, T subject, TypeMap<T, MobileDrivingLicence> subjectMapper, PublicKey credentialBindingKey) {
        if (credentialFormat == CredentialFormat.MSO_MDOC) {
            return getMsoMDoc(subject, subjectMapper, credentialBindingKey);
        } else {
            throw new ServiceException(UNSUPPORTED_CREDENTIAL_FORMAT, "Unsupported credential format");
        }
    }

    private <T> String getMsoMDoc(T subject, TypeMap<T, MobileDrivingLicence> subjectMapper, PublicKey credentialBindingKey) {
        MobileDrivingLicence mdl = subjectMapper.map(subject);
        List<ItemToSign> itemsToSign = new ArrayList<>();
        if (mdl.getAdministrativeNumber() != null)
            itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_ADMINISTRATIVE_NUMBER, new StringElement(mdl.getAdministrativeNumber())));
        if (mdl.getFamilyName() != null)
            itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_FAMILY_NAME, new StringElement(mdl.getFamilyName())));
        if (mdl.getFamilyNameNationalCharacter() != null)
            itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_FAMILY_NAME_NATIONAL_CHARACTER, new StringElement(mdl.getFamilyNameNationalCharacter())));
        if (mdl.getGivenName() != null)
            itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_GIVEN_NAME, new StringElement(mdl.getGivenName())));
        if (mdl.getGivenNameNationalCharacter() != null)
            itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_GIVEN_NAME_NATIONAL_CHARACTER, new StringElement(mdl.getGivenNameNationalCharacter())));
        if (mdl.getBirthDate() != null)
            itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_BIRTH_DATE, getFullDateElement(mdl.getBirthDate())));
        if (mdl.getBirthPlace() != null)
            itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_BIRTH_PLACE, new StringElement(mdl.getBirthPlace())));
        if (mdl.getIssueDate() != null)
            itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_ISSUE_DATE, getFullDateElement(mdl.getIssueDate())));
        if (mdl.getExpiryDate() != null)
            itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_EXPIRY_DATE, getFullDateElement(mdl.getExpiryDate())));
        if (mdl.getIssuingCountry() != null)
            itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_ISSUING_COUNTRY, new StringElement(mdl.getIssuingCountry())));
        if (mdl.getIssuingAuthority() != null)
            itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_ISSUING_AUTHORITY, new StringElement(mdl.getIssuingAuthority())));
        if (mdl.getDocumentNumber() != null)
            itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_DOCUMENT_NUMBER, new StringElement(mdl.getDocumentNumber())));
        if (mdl.getPortrait() != null)
            itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_PORTRAIT, new ByteStringElement(mdl.getPortrait())));
        if (mdl.getSignatureUsualMark() != null)
            itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_SIGNATURE_USUAL_MARK, new ByteStringElement(mdl.getSignatureUsualMark())));
        if (mdl.getDrivingPrivileges() != null && !mdl.getDrivingPrivileges().isEmpty())
            itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_DRIVING_PRIVILEGES, getDrivingPrivilegeItem(mdl)));
        if (mdl.getUnDistinguishingSign() != null)
            itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_UN_DISTINGUISHING_SIGN, new StringElement(mdl.getUnDistinguishingSign())));
        if (mdl.getAgeOver18() != null)
            itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_AGE_OVER_18, new BooleanElement(mdl.getAgeOver18())));
        return mDocService.getMDoc(CredentialDoctype.ORG_ISO_18013_5_1_MDL.getUri(), itemsToSign, credentialBindingKey).toCBORHex();
    }

    private ListElement getDrivingPrivilegeItem(MobileDrivingLicence mdl) {
        return new ListElement(mdl.getDrivingPrivileges().stream()
            .map(dp -> new MapElement(Map.of(
                new MapKey("vehicle_category_code"), new StringElement(dp.getVehicleCategoryCode()),
                new MapKey("issue_date"), getFullDateElement(dp.getIssueDate()),
                new MapKey("expiry_date"), getFullDateElement(dp.getExpiryDate()),
                new MapKey("codes"), new ListElement(dp.getCodes().stream()
                    .map(c -> new MapElement(Map.of(
                        new MapKey("code"), new StringElement(c.getCode()),
                        new MapKey("sign"), new StringElement(c.getSign()),
                        new MapKey("value"), new StringElement(c.getValue())))
                    ).toList()
                ))))
            .toList());
    }

    private ItemToSign getItemToSign(CredentialAttribute credentialAttribute, DataElement elementValue) {
        return ItemToSign.builder()
            .nameSpace(credentialAttribute.getNamespace().getUri())
            .elementIdentifier(credentialAttribute.getUri())
            .elementValue(elementValue)
            .build();
    }

    private FullDateElement getFullDateElement(java.time.LocalDate date) {
        return new FullDateElement(new LocalDate(date.getYear(), date.getMonthValue(), date.getDayOfMonth()), DEFullDateMode.full_date_str);
    }
}
