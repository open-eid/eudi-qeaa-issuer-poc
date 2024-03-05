package ee.ria.eudi.qeaa.issuer.service;

import ee.ria.eudi.qeaa.issuer.error.ServiceException;
import ee.ria.eudi.qeaa.issuer.model.CredentialAttribute;
import ee.ria.eudi.qeaa.issuer.model.CredentialDoctype;
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

import static ee.ria.eudi.qeaa.issuer.model.CredentialAttribute.ORG_ISO_18013_5_1_BIRTH_DATE;
import static ee.ria.eudi.qeaa.issuer.model.CredentialAttribute.ORG_ISO_18013_5_1_DOCUMENT_NUMBER;
import static ee.ria.eudi.qeaa.issuer.model.CredentialAttribute.ORG_ISO_18013_5_1_DRIVING_PRIVILEGES;
import static ee.ria.eudi.qeaa.issuer.model.CredentialAttribute.ORG_ISO_18013_5_1_EXPIRY_DATE;
import static ee.ria.eudi.qeaa.issuer.model.CredentialAttribute.ORG_ISO_18013_5_1_FAMILY_NAME;
import static ee.ria.eudi.qeaa.issuer.model.CredentialAttribute.ORG_ISO_18013_5_1_GIVEN_NAME;
import static ee.ria.eudi.qeaa.issuer.model.CredentialAttribute.ORG_ISO_18013_5_1_ISSUE_DATE;
import static ee.ria.eudi.qeaa.issuer.model.CredentialAttribute.ORG_ISO_18013_5_1_ISSUING_AUTHORITY;
import static ee.ria.eudi.qeaa.issuer.model.CredentialAttribute.ORG_ISO_18013_5_1_ISSUING_COUNTRY;
import static ee.ria.eudi.qeaa.issuer.model.CredentialAttribute.ORG_ISO_18013_5_1_PORTRAIT;
import static ee.ria.eudi.qeaa.issuer.model.CredentialAttribute.ORG_ISO_18013_5_1_UN_DISTINGUISHING_SIGN;

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
        itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_FAMILY_NAME, new StringElement(mobileDrivingLicence.getFamilyName())));
        itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_GIVEN_NAME, new StringElement(mobileDrivingLicence.getGivenName())));
        itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_BIRTH_DATE, getFullDateElement(mobileDrivingLicence.getBirthDate())));
        itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_ISSUE_DATE, getFullDateElement(mobileDrivingLicence.getIssueDate())));
        itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_EXPIRY_DATE, getFullDateElement(mobileDrivingLicence.getExpiryDate())));
        itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_ISSUING_COUNTRY, new StringElement(mobileDrivingLicence.getIssuingCountry())));
        itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_ISSUING_AUTHORITY, new StringElement(mobileDrivingLicence.getIssuingAuthority())));
        itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_DOCUMENT_NUMBER, new StringElement(mobileDrivingLicence.getDocumentNumber())));
        itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_PORTRAIT, new ByteStringElement(mobileDrivingLicence.getPortrait())));
        itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_DRIVING_PRIVILEGES, new ListElement(mobileDrivingLicence.getDrivingPrivileges().stream().map(StringElement::new).toList())));
        itemsToSign.add(getItemToSign(ORG_ISO_18013_5_1_UN_DISTINGUISHING_SIGN, new StringElement(mobileDrivingLicence.getUnDistinguishingSign())));
        return mDocService.getMDoc(CredentialDoctype.ORG_ISO_18013_5_1_MDL.getUri(), itemsToSign, credentialBindingKey).toCBORHex();
    }

    private ItemToSign getItemToSign(CredentialAttribute credentialAttribute, DataElement<?> elementValue) {
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
