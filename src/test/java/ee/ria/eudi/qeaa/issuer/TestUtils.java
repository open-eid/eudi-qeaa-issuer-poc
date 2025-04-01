package ee.ria.eudi.qeaa.issuer;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.upokecenter.cbor.CBORObject;
import id.walt.mdoc.dataelement.MapElement;
import id.walt.mdoc.doc.MDoc;
import id.walt.mdoc.mso.DeviceKeyInfo;
import id.walt.mdoc.mso.MSO;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import org.cose.java.OneKey;

import java.security.PublicKey;
import java.util.Objects;

@UtilityClass
public class TestUtils {

    public JWSAlgorithm getJwsAlgorithm(@NonNull Curve curve) {
        if (curve.equals(Curve.P_256)) {
            return JWSAlgorithm.ES256;
        } else if (curve.equals(Curve.SECP256K1)) {
            return JWSAlgorithm.ES256K;
        } else if (curve.equals(Curve.P_384)) {
            return JWSAlgorithm.ES384;
        } else if (curve.equals(Curve.P_521)) {
            return JWSAlgorithm.ES512;
        } else {
            throw new IllegalArgumentException("Unsupported curve: " + curve.getName());
        }
    }

    @SneakyThrows
    public ECKey generateECKey() {
        return new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.ENCRYPTION).generate();
    }

    @SneakyThrows
    public PublicKey getDevicePublicKey(MDoc mDoc) {
        MSO mso = Objects.requireNonNull(mDoc.getMSO());
        DeviceKeyInfo deviceKeyInfo = mso.getDeviceKeyInfo();
        MapElement deviceKey = deviceKeyInfo.getDeviceKey();
        return new OneKey(CBORObject.DecodeFromBytes(deviceKey.toCBOR())).AsPublicKey();
    }
}
