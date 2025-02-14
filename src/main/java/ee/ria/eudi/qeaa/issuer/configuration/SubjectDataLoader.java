package ee.ria.eudi.qeaa.issuer.configuration;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import ee.ria.eudi.qeaa.issuer.model.Subject;
import ee.ria.eudi.qeaa.issuer.repository.SubjectRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.util.List;

@Slf4j
@Configuration
@Profile("dev")
@RequiredArgsConstructor
public class SubjectDataLoader {
    private final ObjectMapper objectMapper;
    private final SubjectRepository subjectRepository;

    @Value("${eudi.issuer.subject-test-data}")
    private Resource subjectData;

    @PostConstruct
    public void loadSubjectData() throws IOException {
        List<Subject> subjectList = objectMapper.readValue(subjectData.getInputStream(), new TypeReference<>() {
        });
        log.info("Loaded {} subjects: ", subjectList.size());
        subjectList.forEach(subject -> log.info(
            "Administrative number: {}\n" +
                "Family name: {}\n" +
                "Family name national character: {}\n" +
                "Given name: {}\n" +
                "Given name national character: {}\n" +
                "Birth date: {}\n" +
                "Birth place: {}\n" +
                "Issue date: {}\n" +
                "Expiry date: {}\n" +
                "Issuing country: {}\n" +
                "Issuing authority: {}\n" +
                "Document number: {}\n" +
                "Portrait (size): {}\n" +
                "SignatureUsualMark (size): {}\n" +
                "Driving privileges: {}\n" +
                "UN distinguishing sign: {}\n" +
                "Age over 18: {}",
            subject.getAdministrativeNumber(),
            subject.getFamilyName(),
            subject.getFamilyNameNationalCharacter(),
            subject.getGivenName(),
            subject.getGivenNameNationalCharacter(),
            subject.getBirthDate(),
            subject.getBirthPlace(),
            subject.getIssueDate(),
            subject.getExpiryDate(),
            subject.getIssuingCountry(),
            subject.getIssuingAuthority(),
            subject.getDocumentNumber(),
            subject.getPortrait().length,
            subject.getSignatureUsualMark().length,
            subject.getDrivingPrivileges(),
            subject.getUnDistinguishingSign(),
            subject.getAgeOver18()));
        subjectRepository.saveAll(subjectList);
    }
}
