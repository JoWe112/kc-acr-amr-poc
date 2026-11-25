package com.example.keycloak.x509loa;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.OptionalInt;

import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowCallback;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.authenticators.util.AcrStore;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Sets the Level of Authentication (LoA, surfaced as the {@code acr} claim) based solely on
 * the issuing CA of the client certificate.
 *
 * <p>Must run <b>after</b> "X509/Validate Username Form" in the same subflow: that
 * authenticator validates the certificate and identifies the user; this one only grades
 * the login. Steps:</p>
 * <ol>
 *   <li>Fetch the certificate chain via {@link X509ClientCertificateLookup} (works for both
 *       direct mTLS and reverse-proxy header forwarding, depending on the configured lookup).</li>
 *   <li>Read the leaf certificate's Issuer DN and look it up in the configured mapping.</li>
 *   <li>On a match (or with the {@code default-loa} policy) call
 *       {@link AcrStore#setLevelAuthenticated(int)} and store the Issuer DN in the user
 *       session note {@value #ISSUER_DN_NOTE}.</li>
 *   <li>Otherwise fail closed with an error page, stopping the whole flow.</li>
 * </ol>
 *
 * <p>Also implements {@link AuthenticationFlowCallback}. When the top-level flow succeeds it
 * does what Keycloak's own "Condition - Level of Authentication" does, because on the X.509
 * path no such condition is evaluated:</p>
 * <ul>
 *   <li>enforces an <em>essential</em> acr request ({@code claims} parameter) — without this,
 *       a certificate from a lower-level CA would satisfy an essential {@code loa3} request;</li>
 *   <li>copies the LoA map to the user session so SSO re-logins remember the level.</li>
 * </ul>
 */
public class X509IssuerLoaAuthenticator implements AuthenticationFlowCallback {

    /** User session note holding the RFC 2253 Issuer DN of the certificate used to log in. */
    public static final String ISSUER_DN_NOTE = "x509_issuer_dn";

    /** Shown to the end user; deliberately does not reveal which CAs are accepted. */
    static final String ERROR_MESSAGE = "Your certificate was issued by a certificate authority that is not approved for login.";

    private static final Logger LOG = Logger.getLogger(X509IssuerLoaAuthenticator.class);

    private final KeycloakSession session;

    public X509IssuerLoaAuthenticator(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        X509Certificate leaf = getClientCertificate(context);
        if (leaf == null) {
            // The preceding X.509 authenticator should have rejected this already; never grant a level without a cert.
            LOG.warn("No client certificate available; the X.509 issuer LoA authenticator must run after "
                    + "'X509/Validate Username Form' in the same subflow");
            failClosed(context, "no_client_certificate");
            return;
        }

        String issuerDn = leaf.getIssuerX500Principal().getName(); // RFC 2253
        IssuerLoaMapping mapping;
        try {
            AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
            mapping = X509IssuerLoaConfig.fromConfig(cfg == null ? null : cfg.getConfig());
        } catch (IllegalArgumentException e) {
            LOG.errorf("Invalid X.509 issuer LoA configuration in execution '%s': %s", context.getExecution().getId(),
                    e.getMessage());
            failClosed(context, "invalid_x509_loa_configuration");
            return;
        }

        OptionalInt level = mapping.resolve(leaf.getIssuerX500Principal());
        if (level.isEmpty()) {
            LOG.warnf("Rejecting X.509 login: issuer '%s' is not in the LoA mapping and the policy is fail-closed", issuerDn);
            failClosed(context, "x509_issuer_not_mapped");
            return;
        }

        boolean explicitlyMapped = mapping.lookup(leaf.getIssuerX500Principal()).isPresent();
        LOG.debugf("X.509 issuer '%s' -> LoA %d (%s)", issuerDn, level.getAsInt(),
                explicitlyMapped ? "mapped" : "default for unknown issuer");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        authSession.setUserSessionNote(ISSUER_DN_NOTE, issuerDn);
        new AcrStore(context.getSession(), authSession).setLevelAuthenticated(level.getAsInt());

        context.getEvent().detail("x509_issuer_dn", issuerDn).detail("x509_loa", String.valueOf(level.getAsInt()));
        context.success();
    }

    /**
     * Returns the end-entity certificate, or {@code null} if none was presented.
     */
    private X509Certificate getClientCertificate(AuthenticationFlowContext context) {
        X509ClientCertificateLookup lookup = context.getSession().getProvider(X509ClientCertificateLookup.class);
        if (lookup == null) {
            LOG.error("No X509ClientCertificateLookup provider configured");
            return null;
        }
        try {
            X509Certificate[] chain = lookup.getCertificateChain(context.getHttpRequest());
            return (chain == null || chain.length == 0) ? null : chain[0];
        } catch (GeneralSecurityException e) {
            LOG.warnf("Unable to read client certificate chain: %s", e.getMessage());
            return null;
        }
    }

    /**
     * Rejects the login and renders an error page.
     *
     * <p>Passing a challenge response to {@code failure(...)} makes Keycloak return the page
     * immediately instead of throwing; a thrown failure inside an ALTERNATIVE subflow would
     * be swallowed and the next alternative (with the X.509 user still set) would run.</p>
     */
    private void failClosed(AuthenticationFlowContext context, String eventError) {
        context.getEvent().error(eventError);
        Response page = context.form().setError(ERROR_MESSAGE).createErrorPage(Response.Status.UNAUTHORIZED);
        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, page);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // No form of our own.
    }

    /** Called when the X.509 subflow succeeds; nothing to do — the level is set in authenticate(). */
    @Override
    public void onParentFlowSuccess(AuthenticationFlowContext context) {
    }

    /**
     * Runs once after the whole browser flow succeeded (only if this authenticator succeeded
     * in it).
     *
     * <ol>
     *   <li>Fails the login if the client marked the acr as essential and the achieved level is
     *       lower (mirrors {@code ConditionalLoaAuthenticator#onTopFlowSuccess}).</li>
     *   <li>Persists the authenticated levels (incl. timestamps) to the user session so that the
     *       Cookie authenticator can reuse them on SSO and step-up decisions.</li>
     * </ol>
     *
     * @throws AuthenticationFlowException if an essential acr was requested but not reached
     */
    @Override
    public void onTopFlowSuccess(AuthenticationFlowModel topFlow) {
        AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
        if (authSession == null) {
            return;
        }
        AcrStore acrStore = new AcrStore(session, authSession);
        if (acrStore.isLevelOfAuthenticationForced() && !acrStore.isLevelOfAuthenticationSatisfiedFromCurrentAuthentication(topFlow)) {
            String details = String.format("Essential acr not fulfilled by X.509 login. Requested level: %d, fulfilled level: %d",
                    acrStore.getRequestedLevelOfAuthentication(topFlow), acrStore.getLevelOfAuthenticationFromCurrentAuthentication());
            LOG.info(details);
            throw new AuthenticationFlowException(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR, details,
                    Messages.ACR_NOT_FULFILLED);
        }
        String loaMap = authSession.getAuthNote(Constants.LOA_MAP);
        if (loaMap != null) {
            authSession.setUserSessionNote(Constants.LOA_MAP, loaMap);
        }
    }

    @Override
    public boolean requiresUser() {
        // The user is established by the preceding X.509 authenticator.
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
