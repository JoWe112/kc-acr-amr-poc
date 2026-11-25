package com.example.keycloak.x509loa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.OptionalInt;

import javax.security.auth.x500.X500Principal;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.example.keycloak.x509loa.IssuerLoaMapping.UnknownIssuerPolicy;

/**
 * Unit tests for the Issuer DN -> LoA mapping logic.
 */
class IssuerLoaMappingTest {

    private static final String STANDARD = "CN=Test CA Standard,O=Example Org,C=SE";
    private static final String HIGH = "CN=Test CA High Trust,O=Example Org,C=SE";
    private static final String UNMAPPED = "CN=Test CA Unmapped,O=Example Org,C=SE";

    private static final List<String> ENTRIES = List.of(STANDARD + "::2", HIGH + "::3");

    private static IssuerLoaMapping rejectMapping() {
        return IssuerLoaMapping.parse(ENTRIES, UnknownIssuerPolicy.REJECT, 0);
    }

    @Test
    void mapsEachConfiguredIssuerToItsLevel() {
        IssuerLoaMapping m = rejectMapping();
        assertEquals(OptionalInt.of(2), m.resolve(new X500Principal(STANDARD)));
        assertEquals(OptionalInt.of(3), m.resolve(new X500Principal(HIGH)));
        assertEquals(2, m.size());
    }

    @Test
    void unknownIssuerIsRejectedWhenFailClosed() {
        assertTrue(rejectMapping().resolve(new X500Principal(UNMAPPED)).isEmpty());
    }

    @Test
    void unknownIssuerGetsDefaultLoaWhenConfigured() {
        IssuerLoaMapping m = IssuerLoaMapping.parse(ENTRIES, UnknownIssuerPolicy.DEFAULT_LOA, 1);
        assertEquals(OptionalInt.of(1), m.resolve(new X500Principal(UNMAPPED)));
        // An explicit mapping always wins over the default.
        assertEquals(OptionalInt.of(3), m.resolve(new X500Principal(HIGH)));
        assertTrue(m.lookup(new X500Principal(UNMAPPED)).isEmpty(), "lookup() must ignore the default");
    }

    /** Admins paste DNs from many tools; spacing and case differences must not break matching. */
    @ParameterizedTest
    @ValueSource(strings = {
            "CN=Test CA High Trust, O=Example Org, C=SE",          // spaces after commas (RFC 1779 style)
            "cn=test ca high trust,o=example org,c=se",            // lower case
            "  CN=Test CA High Trust,O=Example Org,C=SE  ",        // surrounding whitespace
            "CN=Test  CA High Trust,O=Example Org,C=SE",           // internal double space (canonical form collapses)
            "2.5.4.3=Test CA High Trust,O=Example Org,C=SE"        // OID instead of CN
    })
    void matchingIsInsensitiveToFormattingDifferences(String configuredDn) {
        IssuerLoaMapping m = IssuerLoaMapping.parse(List.of(configuredDn + "::3"), UnknownIssuerPolicy.REJECT, 0);
        assertEquals(OptionalInt.of(3), m.resolve(new X500Principal(HIGH)));
    }

    @Test
    void rdnOrderMatters() {
        // Reversed (LDAP/X.500 display) order is a different DN and must not match silently.
        IssuerLoaMapping m = IssuerLoaMapping.parse(List.of("C=SE,O=Example Org,CN=Test CA High Trust::3"),
                UnknownIssuerPolicy.REJECT, 0);
        assertTrue(m.resolve(new X500Principal(HIGH)).isEmpty());
    }

    @Test
    void issuerWithSameCnButDifferentOrganisationDoesNotMatch() {
        // Guards against "CN-only" matching: a rogue CA re-using the CN must not inherit the level.
        assertTrue(rejectMapping().resolve(new X500Principal("CN=Test CA High Trust,O=Evil Corp,C=SE")).isEmpty());
    }

    @Test
    void dnContainingSeparatorCharactersIsSplitOnLastSeparator() {
        String dn = "CN=CA::with colons,O=Example Org,C=SE";
        IssuerLoaMapping m = IssuerLoaMapping.parse(List.of(dn + "::2"), UnknownIssuerPolicy.REJECT, 0);
        assertEquals(OptionalInt.of(2), m.resolve(new X500Principal(dn)));
    }

    @Test
    void blankEntriesAreIgnoredAndNullListIsEmpty() {
        assertEquals(1, IssuerLoaMapping.parse(Arrays.asList("", "  ", null, HIGH + "::3"), UnknownIssuerPolicy.REJECT, 0).size());
        assertEquals(0, IssuerLoaMapping.parse(null, UnknownIssuerPolicy.REJECT, 0).size());
    }

    @Test
    void levelZeroIsAllowed() {
        IssuerLoaMapping m = IssuerLoaMapping.parse(List.of(STANDARD + "::0"), UnknownIssuerPolicy.REJECT, 0);
        assertEquals(OptionalInt.of(0), m.resolve(new X500Principal(STANDARD)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            STANDARD,                         // missing separator
            STANDARD + "::",                  // missing level
            "::2",                            // missing DN
            STANDARD + "::two",               // non-numeric level
            STANDARD + "::-1",                // negative level
            "/C=SE/O=Example Org/CN=Test CA Standard::2" // OpenSSL oneline format is not a valid RFC 2253 DN
    })
    void malformedEntriesAreRejected(String entry) {
        assertThrows(IllegalArgumentException.class,
                () -> IssuerLoaMapping.parse(List.of(entry), UnknownIssuerPolicy.REJECT, 0));
    }

    @Test
    void duplicateIssuerIsRejectedEvenWithDifferentFormatting() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> IssuerLoaMapping.parse(List.of(HIGH + "::3", "cn=test ca high trust, o=example org, c=se::2"),
                        UnknownIssuerPolicy.REJECT, 0));
        assertTrue(e.getMessage().contains("Duplicate"));
    }

    @Test
    void negativeDefaultLoaIsRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> IssuerLoaMapping.parse(ENTRIES, UnknownIssuerPolicy.DEFAULT_LOA, -1));
    }
}
