package ee.ria.eudi.qeaa.issuer.repository;

import ee.ria.eudi.qeaa.issuer.model.Subject;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SubjectRepository extends JpaRepository<Subject, Long> {

    Optional<Subject> findByAdministrativeNumber(String administrativeNumber);
}
