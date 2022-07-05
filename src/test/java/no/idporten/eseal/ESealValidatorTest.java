package no.idporten.eseal;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("When validating certificates")
public class ESealValidatorTest {

    @DisplayName("then valid certificates are accepted")
    @Test
    void testValidateValidCertificate() throws Exception {
        ESealValidator eSealValidator = new ESealValidatorBuilder(Environment.TEST).build();
        // TODO see tests in maskinporten - generer en testca og se mer på crl
    }

}
