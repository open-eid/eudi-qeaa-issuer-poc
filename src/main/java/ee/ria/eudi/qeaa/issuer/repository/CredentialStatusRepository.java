package ee.ria.eudi.qeaa.issuer.repository;

import ee.ria.eudi.qeaa.issuer.model.CredentialStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface CredentialStatusRepository extends JpaRepository<CredentialStatus, Long> {

    @Query("select c.statusIndex from CredentialStatus c where c.statusListUri = ?1")
    List<Integer> findUsedStatusIndexes(String statusListUri);
}
