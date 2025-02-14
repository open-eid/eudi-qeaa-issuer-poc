package ee.ria.eudi.qeaa.issuer.service;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class DrivingPrivilege {
    private String vehicleCategoryCode;
    private LocalDate issueDate;
    private LocalDate expiryDate;
    private List<Code> codes;

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class Code {
        private String code;
        private String sign;
        private String value;
    }
}
