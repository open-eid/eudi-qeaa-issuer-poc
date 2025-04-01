package ee.ria.eudi.qeaa.issuer.service;

import ee.ria.eudi.qeaa.issuer.error.ServiceException;
import ee.ria.eudi.qeaa.issuer.model.CredentialStatus;
import ee.ria.eudi.qeaa.issuer.model.Subject;
import ee.ria.eudi.qeaa.issuer.repository.CredentialStatusRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.util.Pair;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialStatusService {
    public static final String STATUS_LIST_URI = "https://aarmam.github.io/statuslists/%d";
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final int STATUS_LIST_SIZE = 1048576;
    private final CredentialStatusRepository credentialStatusRepository;

    public CredentialStatus createCredentialStatus(Subject subject) {
        Pair<Integer, List<Integer>> indexInfo = getUsedStatusIndexes(1);
        List<Integer> usedStatusIndexes = indexInfo.getSecond();
        int statusListIndex = indexInfo.getFirst();
        int freeStatusIndex = secureRandom.ints(0, STATUS_LIST_SIZE)
            .filter(statusIndex -> !usedStatusIndexes.contains(statusIndex))
            .findFirst()
            .orElseThrow(() -> new ServiceException("Unable to find free status index"));

        CredentialStatus credentialStatus = CredentialStatus.builder()
            .subject(subject)
            .statusListUri(STATUS_LIST_URI.formatted(statusListIndex))
            .statusIndex(freeStatusIndex)
            .build();
        credentialStatusRepository.save(credentialStatus);
        log.info("Credential status: {}", credentialStatus);
        return credentialStatus;
    }

    private Pair<Integer, List<Integer>> getUsedStatusIndexes(int statusListIndex) {
        List<Integer> usedStatusIndexes = credentialStatusRepository.findUsedStatusIndexes(STATUS_LIST_URI.formatted(statusListIndex));
        if (usedStatusIndexes.size() == STATUS_LIST_SIZE) {
            return getUsedStatusIndexes(++statusListIndex);
        } else {
            return Pair.of(statusListIndex, usedStatusIndexes);
        }
    }
}
