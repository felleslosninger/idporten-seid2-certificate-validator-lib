package no.idporten.eseal;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("When resolving environment")
public class EnvironmentTest {

    @DisplayName("then test environment can be resolved")
    @Test
    void testResolveTestEnvironment() {
        assertSame(Environment.TEST, Environment.of("test"));
    }

    @DisplayName("then prod environment can be resolved")
    @Test
    void testResolveProdEnvironment() {
        assertSame(Environment.PROD, Environment.of("prod"));
    }

    @DisplayName("then unknown environments are rejected")
    @Test
    void testRejectUnkownEnvironment() {
        assertAll(
                () -> assertThrows(NullPointerException.class, () -> Environment.of(null)),
                () -> assertThrows(IllegalArgumentException.class, () -> Environment.of("tezt"))
        );
    }

}
