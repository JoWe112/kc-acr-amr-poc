package com.example.keycloak.x509loa;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalInt;

import javax.security.auth.x500.X500Principal;

/**
 * Pure (Keycloak-independent) mapping from an issuing CA's Distinguished Name to a
 * Level of Authentication (LoA).
 *
 * <p>Each configuration entry has the form {@code <Issuer DN>::<level>}, for example
 * {@code CN=Test CA High Trust,O=Example Org,C=SE::3}. DNs are compared in
 * {@link X500Principal#CANONICAL} form, so differences in whitespace, letter case of
 * attribute values and attribute-type spelling ({@code EMAILADDRESS} vs OID) do not
 * matter. The <em>order</em> of RDNs does matter: use RFC 2253 order (most specific
 * first, i.e. {@code CN=...,O=...,C=...}), which is what
 * {@code X509Certificate#getIssuerX500Principal().getName()} returns.</p>
 *
 * <p>Instances are immutable and thread safe.</p>
 */
public final class IssuerLoaMapping {

    /** Separator between the Issuer DN and the level in a configuration entry. */
    public static final String ENTRY_SEPARATOR = "::";

    /** What to do when the certificate was issued by a CA that is not in the mapping. */
    public enum UnknownIssuerPolicy {
        /** Fail closed: the X.509 login is rejected. */
        REJECT,
        /** Accept the login with the configured default LoA. */
        DEFAULT_LOA
    }

    /** Canonical issuer DN -> LoA. Insertion order kept for predictable logging. */
    private final Map<String, Integer> levelsByCanonicalDn;
    private final UnknownIssuerPolicy unknownIssuerPolicy;
    private final int defaultLoa;

    private IssuerLoaMapping(Map<String, Integer> levelsByCanonicalDn, UnknownIssuerPolicy policy, int defaultLoa) {
        this.levelsByCanonicalDn = Collections.unmodifiableMap(levelsByCanonicalDn);
        this.unknownIssuerPolicy = policy;
        this.defaultLoa = defaultLoa;
    }

    /**
     * Parses and validates the mapping.
     *
     * @param entries    raw {@code <Issuer DN>::<level>} entries; blank entries are ignored
     * @param policy     behaviour for issuers that are not mapped
     * @param defaultLoa LoA used when {@code policy == DEFAULT_LOA}; must be &gt;= 0
     * @return the validated mapping
     * @throws IllegalArgumentException on a malformed entry, a non-numeric or negative level,
     *                                  an unparsable DN, a duplicate DN, or an invalid default LoA
     */
    public static IssuerLoaMapping parse(List<String> entries, UnknownIssuerPolicy policy, int defaultLoa) {
        Objects.requireNonNull(policy, "policy");
        if (policy == UnknownIssuerPolicy.DEFAULT_LOA && defaultLoa < 0) {
            throw new IllegalArgumentException("Default LoA must be >= 0, was " + defaultLoa);
        }

        Map<String, Integer> levels = new LinkedHashMap<>();
        if (entries != null) {
            for (String raw : entries) {
                if (raw == null || raw.isBlank()) {
                    continue;
                }
                // The DN itself may legitimately contain ':' (e.g. in an OID value), so split on the LAST separator.
                int idx = raw.lastIndexOf(ENTRY_SEPARATOR);
                if (idx <= 0 || idx + ENTRY_SEPARATOR.length() >= raw.length()) {
                    throw new IllegalArgumentException(
                            "Invalid mapping entry '" + raw + "': expected '<Issuer DN>" + ENTRY_SEPARATOR + "<level>'");
                }
                String dn = raw.substring(0, idx).trim();
                String levelStr = raw.substring(idx + ENTRY_SEPARATOR.length()).trim();

                int level;
                try {
                    level = Integer.parseInt(levelStr);
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("Invalid level '" + levelStr + "' in mapping entry '" + raw + "'", e);
                }
                if (level < 0) {
                    throw new IllegalArgumentException("Level must be >= 0 in mapping entry '" + raw + "'");
                }

                String canonical = canonicalize(dn);
                if (levels.putIfAbsent(canonical, level) != null) {
                    throw new IllegalArgumentException("Duplicate Issuer DN in mapping: '" + dn + "'");
                }
            }
        }
        return new IssuerLoaMapping(levels, policy, defaultLoa);
    }

    /**
     * Converts a DN string to its canonical form for comparison.
     *
     * @throws IllegalArgumentException if the string is not a valid RFC 1779/2253 DN
     *                                  (e.g. OpenSSL "oneline" format {@code /C=SE/O=...})
     */
    public static String canonicalize(String dn) {
        if (dn == null || dn.isBlank()) {
            throw new IllegalArgumentException("Issuer DN must not be empty");
        }
        try {
            return new X500Principal(dn.trim()).getName(X500Principal.CANONICAL);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Not a valid RFC 2253 Distinguished Name: '" + dn + "'", e);
        }
    }

    /**
     * Returns the LoA explicitly mapped for the issuer, ignoring the unknown-issuer policy.
     */
    public OptionalInt lookup(X500Principal issuer) {
        Objects.requireNonNull(issuer, "issuer");
        Integer level = levelsByCanonicalDn.get(issuer.getName(X500Principal.CANONICAL));
        return level == null ? OptionalInt.empty() : OptionalInt.of(level);
    }

    /**
     * Resolves the LoA to grant for a certificate from {@code issuer}, applying the
     * unknown-issuer policy.
     *
     * @return the level to set, or empty if the login must be rejected (fail closed)
     */
    public OptionalInt resolve(X500Principal issuer) {
        OptionalInt mapped = lookup(issuer);
        if (mapped.isPresent()) {
            return mapped;
        }
        return unknownIssuerPolicy == UnknownIssuerPolicy.DEFAULT_LOA ? OptionalInt.of(defaultLoa) : OptionalInt.empty();
    }

    /** Number of mapped issuers. */
    public int size() {
        return levelsByCanonicalDn.size();
    }

    public UnknownIssuerPolicy getUnknownIssuerPolicy() {
        return unknownIssuerPolicy;
    }

    public int getDefaultLoa() {
        return defaultLoa;
    }

    @Override
    public String toString() {
        return "IssuerLoaMapping{levels=" + levelsByCanonicalDn + ", unknownIssuerPolicy=" + unknownIssuerPolicy
                + ", defaultLoa=" + defaultLoa + "}";
    }
}
