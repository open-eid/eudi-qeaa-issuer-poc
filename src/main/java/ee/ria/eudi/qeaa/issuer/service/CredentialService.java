package ee.ria.eudi.qeaa.issuer.service;

import ee.ria.eudi.qeaa.issuer.error.ServiceException;
import ee.ria.eudi.qeaa.issuer.model.CredentialFormat;
import ee.ria.eudi.qeaa.issuer.model.ItemToSign;
import ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence;
import id.walt.mdoc.dataelement.ByteStringElement;
import id.walt.mdoc.dataelement.DEFullDateMode;
import id.walt.mdoc.dataelement.DataElement;
import id.walt.mdoc.dataelement.FullDateElement;
import id.walt.mdoc.dataelement.ListElement;
import id.walt.mdoc.dataelement.StringElement;
import kotlinx.datetime.LocalDate;
import lombok.RequiredArgsConstructor;
import org.modelmapper.TypeMap;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.DOC_TYPE_ORG_ISO_18013_5_1_MDL;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.NAMESPACE_ORG_ISO_18013_5_1;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.BIRTH_DATE;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.DOCUMENT_NUMBER;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.DRIVING_PRIVILEGES;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.EXPIRY_DATE;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.FAMILY_NAME;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.GIVEN_NAME;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.ISSUE_DATE;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.ISSUING_AUTHORITY;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.ISSUING_COUNTRY;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.PORTRAIT;
import static ee.ria.eudi.qeaa.issuer.model.MobileDrivingLicence.SupportedClaims.UN_DISTINGUISHING_SIGN;

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
            throw new ServiceException("Unsupported credential format");
        }
    }

    private <T> String getMsoMDoc(T subject, TypeMap<T, MobileDrivingLicence> subjectMapper, PublicKey credentialBindingKey) {
        MobileDrivingLicence mobileDrivingLicence = subjectMapper.map(subject);
        List<ItemToSign> itemsToSign = new ArrayList<>();
        itemsToSign.add(getItemToSign(FAMILY_NAME.toString(), new StringElement(mobileDrivingLicence.getFamilyName())));
        itemsToSign.add(getItemToSign(GIVEN_NAME.toString(), new StringElement(mobileDrivingLicence.getGivenName())));
        itemsToSign.add(getItemToSign(BIRTH_DATE.toString(), getFullDateElement(mobileDrivingLicence.getBirthDate())));
        itemsToSign.add(getItemToSign(ISSUE_DATE.toString(), getFullDateElement(mobileDrivingLicence.getIssueDate())));
        itemsToSign.add(getItemToSign(EXPIRY_DATE.toString(), getFullDateElement(mobileDrivingLicence.getExpiryDate())));
        itemsToSign.add(getItemToSign(ISSUING_COUNTRY.toString(), new StringElement(mobileDrivingLicence.getIssuingCountry())));
        itemsToSign.add(getItemToSign(ISSUING_AUTHORITY.toString(), new StringElement(mobileDrivingLicence.getIssuingAuthority())));
        itemsToSign.add(getItemToSign(DOCUMENT_NUMBER.toString(), new StringElement(mobileDrivingLicence.getDocumentNumber())));
        itemsToSign.add(getItemToSign(PORTRAIT.toString(), new ByteStringElement(mobileDrivingLicence.getPortrait())));
        itemsToSign.add(getItemToSign(DRIVING_PRIVILEGES.toString(), new ListElement(mobileDrivingLicence.getDrivingPrivileges().stream().map(StringElement::new).toList())));
        itemsToSign.add(getItemToSign(UN_DISTINGUISHING_SIGN.toString(), new StringElement(mobileDrivingLicence.getUnDistinguishingSign())));
        return mDocService.getMDoc(DOC_TYPE_ORG_ISO_18013_5_1_MDL, itemsToSign, credentialBindingKey).toCBORHex();
    }

    private ItemToSign getItemToSign(String elementIdentifier, DataElement<?> elementValue) {
        return ItemToSign.builder()
            .nameSpace(NAMESPACE_ORG_ISO_18013_5_1)
            .elementIdentifier(elementIdentifier)
            .elementValue(elementValue)
            .build();
    }

    private FullDateElement getFullDateElement(java.time.LocalDate date) {
        return new FullDateElement(new LocalDate(date.getYear(), date.getMonthValue(), date.getDayOfMonth()), DEFullDateMode.full_date_str);
    }
}
