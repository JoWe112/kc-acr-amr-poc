package com.example.keycloak.x509loa;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowCallbackFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * Factory for {@link X509IssuerLoaAuthenticator}. Registered through
 * {@code META-INF/services/org.keycloak.authentication.AuthenticatorFactory}.
 *
 * <p>Implements {@link AuthenticationFlowCallbackFactory} so that Keycloak invokes the
 * authenticator's {@code onTopFlowSuccess} callback after the whole flow succeeds.</p>
 */
public class X509IssuerLoaAuthenticatorFactory implements AuthenticationFlowCallbackFactory {

    public static final String PROVIDER_ID = "x509-issuer-loa-authenticator";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
            .property()
                .name(X509IssuerLoaConfig.ISSUER_MAPPING)
                .label("Issuer DN to LoA mapping")
                .helpText("One entry per issuing CA in the form '<Issuer DN>::<level>', e.g. "
                        + "'CN=Test CA High Trust,O=Example Org,C=SE::3'. The DN must be in RFC 2253 order "
                        + "(most specific RDN first, as printed by 'openssl x509 -noout -issuer -nameopt RFC2253'). "
                        + "Whitespace and letter case are normalised before comparison. "
                        + "The level must exist in the realm's ACR to LoA mapping.")
                .type(ProviderConfigProperty.MULTIVALUED_STRING_TYPE)
                .add()
            .property()
                .name(X509IssuerLoaConfig.UNKNOWN_ISSUER_POLICY)
                .label("Unknown issuer policy")
                .helpText("'reject' (fail closed, recommended): an X.509 login with a certificate from an unmapped CA "
                        + "is denied. 'default-loa': the login is accepted with the default LoA below.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .options(X509IssuerLoaConfig.POLICY_REJECT, X509IssuerLoaConfig.POLICY_DEFAULT_LOA)
                .defaultValue(X509IssuerLoaConfig.POLICY_REJECT)
                .add()
            .property()
                .name(X509IssuerLoaConfig.DEFAULT_LOA)
                .label("Default LoA for unknown issuers")
                .helpText("Level granted to certificates from unmapped CAs. Only used when the unknown issuer policy is "
                        + "'default-loa'.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("1")
                .add()
            .build();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "X509 Issuer LoA Authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return "x509";
    }

    @Override
    public String getHelpText() {
        return "Sets the Level of Authentication (acr) from the Issuer DN of the client certificate. "
                + "Place directly after 'X509/Validate Username Form' in the same subflow.";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new X509IssuerLoaAuthenticator(session);
    }

    /**
     * Note: Keycloak 26.6 has no hook for validating authenticator config on save. An invalid
     * mapping is therefore detected at login time, logged at ERROR level and fails closed.
     */
    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
