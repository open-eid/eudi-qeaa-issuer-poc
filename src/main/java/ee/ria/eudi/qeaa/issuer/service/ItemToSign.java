package ee.ria.eudi.qeaa.issuer.service;

import id.walt.mdoc.dataelement.DataElement;
import lombok.Builder;

@Builder
public record ItemToSign(
    String nameSpace,
    String elementIdentifier,
    DataElement elementValue) {

}
