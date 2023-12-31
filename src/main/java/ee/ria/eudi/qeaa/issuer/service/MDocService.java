package ee.ria.eudi.qeaa.issuer.service;


import COSE.OneKey;
import ee.ria.eudi.qeaa.issuer.configuration.properties.IssuerProperties;
import ee.ria.eudi.qeaa.issuer.model.ItemToSign;
import id.walt.mdoc.SimpleCOSECryptoProvider;
import id.walt.mdoc.dataelement.DataElement;
import id.walt.mdoc.dataelement.MapElement;
import id.walt.mdoc.doc.MDoc;
import id.walt.mdoc.doc.MDocBuilder;
import id.walt.mdoc.mso.DeviceKeyInfo;
import id.walt.mdoc.mso.ValidityInfo;
import kotlinx.datetime.Clock;
import kotlinx.datetime.Instant;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.util.List;

import static ee.ria.eudi.qeaa.issuer.configuration.MDocConfiguration.KEY_ID_ISSUER;

/**
 * The MDocService is responsible for constructing and signing generic MDoc credentials. It encapsulates the logic
 * for creating the structure of an MDoc, adding items to sign, and performing the cryptographic signing operation.
 * This service acts as a specialized component within the credential generation process, focusing on the specifics
 * of the MDoc format.
 */
@Service
@RequiredArgsConstructor
public class MDocService {
    private final SimpleCOSECryptoProvider issuerCryptoProvider;
    private final IssuerProperties.Issuer issuerProperties;

    protected MDoc getMDoc(String docType, List<ItemToSign> itemsToSign, PublicKey deviceKey) {
        ValidityInfo validityInfo = getValidityInfo();
        DeviceKeyInfo deviceKeyInfo = getDeviceKeyInfo(deviceKey);
        MDocBuilder mDocBuilder = new MDocBuilder(docType);
        itemsToSign.forEach(i -> mDocBuilder.addItemToSign(i.nameSpace(), i.elementIdentifier(), i.elementValue()));
        return mDocBuilder.sign(validityInfo, deviceKeyInfo, issuerCryptoProvider, KEY_ID_ISSUER);
    }

    private ValidityInfo getValidityInfo() {
        long validityTimeInSeconds = issuerProperties.credential().validity().toSeconds();
        Instant signedAt = Clock.System.INSTANCE.now();
        Instant validTo = Instant.Companion.fromEpochSeconds(signedAt.getEpochSeconds() + validityTimeInSeconds, 0);
        return new ValidityInfo(signedAt, signedAt, validTo, null);
    }

    private DeviceKeyInfo getDeviceKeyInfo(PublicKey deviceKey) {
        OneKey key = getDeviceKey(deviceKey);
        MapElement deviceKeyDataElement = DataElement.Companion.fromCBOR(key.AsCBOR().EncodeToBytes());
        return new DeviceKeyInfo(deviceKeyDataElement, null, null);
    }

    @SneakyThrows
    private OneKey getDeviceKey(PublicKey deviceKey) {
        return new OneKey(deviceKey, null);
    }
}
