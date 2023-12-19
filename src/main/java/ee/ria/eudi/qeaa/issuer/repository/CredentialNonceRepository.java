package ee.ria.eudi.qeaa.issuer.repository;

import ee.ria.eudi.qeaa.issuer.model.CredentialNonce;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CredentialNonceRepository extends JpaRepository<CredentialNonce, String> {

    CredentialNonce findByAccessTokenHash(String accessTokenHash);
}
