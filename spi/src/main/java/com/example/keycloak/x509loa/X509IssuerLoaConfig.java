package com.example.keycloak.x509loa;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import com.example.keycloak.x509loa.IssuerLoaMapping.UnknownIssuerPolicy;

/**
 * Translates the raw Keycloak authenticator configuration (a {@code Map<String,String>})
 * into an {@link IssuerLoaMapping}. Kept free of Keycloak types so it can be unit tested
 * without a running server.
 */
public final class X509IssuerLoaConfig {

    /** Multivalued list of {@code <Issuer DN>::<level>} entries. */
    public static final String ISSUER_MAPPING = "x509loa.issuer-mapping";
    /** {@code reject} (fail closed, default) or {@code default-loa}. */
    public static final String UNKNOWN_ISSUER_POLICY = "x509loa.unknown-issuer-policy";
    /** LoA used for unmapped issuers when the policy is {@code default-loa}. */
    public static final String DEFAULT_LOA = "x509loa.default-loa";

    public static final String POLICY_REJECT = "reject";
    public static final String POLICY_DEFAULT_LOA = "default-loa";

    /** Keycloak stores multivalued config properties joined with this delimiter (Constants.CFG_DELIMITER). */
    static final String MULTIVALUE_DELIMITER = "##";

    private X509IssuerLoaConfig() {
    }

    /**
     * Builds the mapping from an authenticator config map.
     *
     * @param config the {@code AuthenticatorConfigModel#getConfig()} map; {@code null} is treated as empty
     *               (which, with the default policy, rejects every certificate)
     * @throws IllegalArgumentException when the configuration is invalid
     */
    public static IssuerLoaMapping fromConfig(Map<String, String> config) {
        Map<String, String> cfg = config == null ? Map.of() : config;

        List<String> entries = splitMultivalued(cfg.get(ISSUER_MAPPING));
        UnknownIssuerPolicy policy = parsePolicy(cfg.get(UNKNOWN_ISSUER_POLICY));

        int defaultLoa = 0;
        if (policy == UnknownIssuerPolicy.DEFAULT_LOA) {
            String raw = cfg.get(DEFAULT_LOA);
            if (raw == null || raw.isBlank()) {
                throw new IllegalArgumentException("'" + DEFAULT_LOA + "' is required when the unknown issuer policy is '"
                        + POLICY_DEFAULT_LOA + "'");
            }
            try {
                defaultLoa = Integer.parseInt(raw.trim());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid default LoA '" + raw + "'", e);
            }
        }
        return IssuerLoaMapping.parse(entries, policy, defaultLoa);
    }

    /** Missing/blank -> REJECT, so that a half-configured authenticator fails closed. */
    static UnknownIssuerPolicy parsePolicy(String raw) {
        if (raw == null || raw.isBlank() || POLICY_REJECT.equalsIgnoreCase(raw.trim())) {
            return UnknownIssuerPolicy.REJECT;
        }
        if (POLICY_DEFAULT_LOA.equalsIgnoreCase(raw.trim())) {
            return UnknownIssuerPolicy.DEFAULT_LOA;
        }
        throw new IllegalArgumentException("Unknown issuer policy '" + raw + "', expected '" + POLICY_REJECT + "' or '"
                + POLICY_DEFAULT_LOA + "'");
    }

    static List<String> splitMultivalued(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        return Arrays.stream(raw.split(MULTIVALUE_DELIMITER)).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }
}
