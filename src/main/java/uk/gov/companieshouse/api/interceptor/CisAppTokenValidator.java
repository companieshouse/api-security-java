package uk.gov.companieshouse.api.interceptor;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Validates application authentication tokens in incoming HTTP requests.
 * Checks for the presence and validity of JWT tokens, ensuring required claims
 * such as tenant ID and client IDs are present and correct.
 * Used by {@link CisAppAuthenticationInterceptor} to enforce application-level security.
 * <p>
 * Intended for use in Spring Boot applications to verify application tokens.
 */

public class CisAppTokenValidator {

    private static final String MS_LOGIN_BASE_URL = "https://login.microsoftonline.com/";
    private static final String TENANT_ID_CLAIM_NAME = "tid";
    private static final String APP_ID_CLAIM_NAME = "appid";
    private static final String AUTH_ACCESS_TOKEN_HEADER_KEY = "x-oauth-access-token";

    private final String tenantId;
    private final String logicAppClientId;
    private final String cisAppClientId;

    private final AtomicReference<JWKSet> jwkSetCache = new AtomicReference<>();

    public CisAppTokenValidator(String tenantId, String logicAppClientId, String cisAppClientId) {
        this.tenantId = tenantId;
        this.logicAppClientId = logicAppClientId;
        this.cisAppClientId = cisAppClientId;
    }

    public boolean hasValidApplicationToken(HttpServletRequest request) {
        String token = extractTokenFromRequest(request);
        if (token == null || token.isEmpty()) {
            return false;
        }
        return validateToken(token);
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        return request.getHeader(AUTH_ACCESS_TOKEN_HEADER_KEY);
    }

    protected boolean validateToken(String token) {

      try {
            SignedJWT signedJwt = SignedJWT.parse(token);

            if (isInvalidSignature(signedJwt)) {
                return false;
            }

            JWTClaimsSet claims = signedJwt.getJWTClaimsSet();
            return verifyTokenClaimSet(claims);

        } catch (Exception e) {
            return false;
        }
    }

    private boolean isInvalidSignature(SignedJWT signedJwt) throws Exception {
        String keyId = signedJwt.getHeader().getKeyID();
        RSAPublicKey publicKey = getPublicKeyFromAzureADWithCache(keyId);
        JWSVerifier verifier = new RSASSAVerifier(publicKey);
        return !signedJwt.verify(verifier);
    }

    private RSAPublicKey getPublicKeyFromAzureADWithCache(String keyId) throws Exception {
        final String KEYS_URL = MS_LOGIN_BASE_URL + tenantId + "/discovery/v2.0/keys";

        JWKSet jwkSet = jwkSetCache.get();
        if (jwkSet == null) {
            jwkSet = JWKSet.load(new URI(KEYS_URL).toURL());
            jwkSetCache.set(jwkSet);
        }

        JWK jwk = jwkSet.getKeyByKeyId(keyId);
        if (jwk == null) {
            // Refresh cache if key not found
            jwkSet = JWKSet.load(new URI(KEYS_URL).toURL());
            jwkSetCache.set(jwkSet);
            jwk = jwkSet.getKeyByKeyId(keyId);
        }

        if (!(jwk instanceof RSAKey)) {
            throw new IllegalArgumentException("RSA key not found for keyId: " + keyId);
        }

        return ((RSAKey) jwk).toRSAPublicKey();
    }

    protected boolean verifyTokenClaimSet(JWTClaimsSet claims) {
        return verifyAudience(cisAppClientId, claims.getAudience())
                && verifyAppId(logicAppClientId, claims.getClaim(APP_ID_CLAIM_NAME))
                && verifyIssuer(claims.getIssuer())
                && verifyTenant(claims.getClaim(TENANT_ID_CLAIM_NAME))
                && claims.getExpirationTime().after(new java.util.Date())
                && claims.getNotBeforeTime().before(new java.util.Date());
    }

    public boolean verifyAudience (String expectedClientId, List<String> claimsAudience) {
        String expectedAudience = "api://" + expectedClientId;
        return claimsAudience.contains(expectedAudience);
    }

    public boolean verifyAppId (String expectedClientId, Object claimsAppId) {
        return expectedClientId.equals(claimsAppId);
    }

    protected boolean verifyIssuer (String claimsIssuer) {
        String expectedIssuer = "https://sts.windows.net/" + tenantId + "/";
        return expectedIssuer.equals(claimsIssuer);
    }

    protected boolean verifyTenant (Object claimsTenantId) {
        return tenantId.equals(claimsTenantId);
    }

}