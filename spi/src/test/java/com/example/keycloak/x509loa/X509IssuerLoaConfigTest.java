package com.example.keycloak.x509loa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;

import javax.security.auth.x500.X500Principal;

import org.junit.jupiter.api.Test;

import com.example.keycloak.x509loa.IssuerLoaMapping.UnknownIssuerPolicy;

/**
 * Tests the translation of the raw Keycloak authenticator config map into a mapping,
 * using exactly the format Keycloak persists (multivalued values joined with "##").
 */
class X509IssuerLoaConfigTest {

    private static final String STANDARD = "CN=Test CA Standard,O=Example Org,C=SE";
    private static final String HIGH = "CN=Test CA High Trust,O=Example Org,C=SE";
    private static final String UNMAPPED = "CN=Test CA Unmapped,O=Example Org,C=SE";

    private static Map<String, String> config(String policy, String defaultLoa) {
        Map<String, String> cfg = new HashMap<>();
        cfg.put(X509IssuerLoaConfig.ISSUER_MAPPING, STANDARD + "::2##" + HIGH + "::3");
        if (policy != null) cfg.put(X509IssuerLoaConfig.UNKNOWN_ISSUER_POLICY, policy);
        if (defaultLoa != null) cfg.put(X509IssuerLoaConfig.DEFAULT_LOA, defaultLoa);
        return cfg;
    }

    @Test
    void parsesKeycloakMultivaluedFormat() {
        IssuerLoaMapping m = X509IssuerLoaConfig.fromConfig(config("reject", null));
        assertEquals(2, m.size());
        assertEquals(OptionalInt.of(2), m.resolve(new X500Principal(STANDARD)));
        assertEquals(OptionalInt.of(3), m.resolve(new X500Principal(HIGH)));
    }

    @Test
    void missingPolicyDefaultsToFailClosed() {
        IssuerLoaMapping m = X509IssuerLoaConfig.fromConfig(config(null, "1"));
        assertEquals(UnknownIssuerPolicy.REJECT, m.getUnknownIssuerPolicy());
        assertTrue(m.resolve(new X500Principal(UNMAPPED)).isEmpty());
    }

    @Test
    void nullConfigRejectsEverything() {
        IssuerLoaMapping m = X509IssuerLoaConfig.fromConfig(null);
        assertEquals(0, m.size());
        assertTrue(m.resolve(new X500Principal(HIGH)).isEmpty());
    }

    @Test
    void defaultLoaPolicyUsesConfiguredLevel() {
        IssuerLoaMapping m = X509IssuerLoaConfig.fromConfig(config("default-loa", " 1 "));
        assertEquals(OptionalInt.of(1), m.resolve(new X500Principal(UNMAPPED)));
    }

    @Test
    void defaultLoaPolicyRequiresDefaultLevel() {
        assertThrows(IllegalArgumentException.class, () -> X509IssuerLoaConfig.fromConfig(config("default-loa", null)));
        assertThrows(IllegalArgumentException.class, () -> X509IssuerLoaConfig.fromConfig(config("default-loa", "high")));
    }

    @Test
    void defaultLoaIsIgnoredWhenRejecting() {
        // A garbage default must not break a fail-closed configuration that never uses it.
        IssuerLoaMapping m = X509IssuerLoaConfig.fromConfig(config("reject", "garbage"));
        assertEquals(UnknownIssuerPolicy.REJECT, m.getUnknownIssuerPolicy());
    }

    @Test
    void unknownPolicyValueIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> X509IssuerLoaConfig.fromConfig(config("allow-all", null)));
    }

    @Test
    void splitMultivaluedDropsEmptyParts() {
        assertEquals(List.of("a", "b"), X509IssuerLoaConfig.splitMultivalued("a####b## "));
        assertEquals(List.of(), X509IssuerLoaConfig.splitMultivalued(null));
    }
}
