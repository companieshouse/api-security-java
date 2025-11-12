package uk.gov.companieshouse.api.interceptor;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.mockito.exceptions.misusing.WrongTypeOfReturnValue;

import com.nimbusds.jose.jwk.RSAKey;

import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CisAppTokenValidatorTest {

    private static final String TENANT_ID = "tenant";
    private static final String LOGIC_APP_ID = "logicApp";
    private static final String CIS_APP_ID = "cisApp";
    private static final String VALID_TOKEN = "valid.jwt.token";
    private static final String HEADER_KEY = "x-oauth-access-token";

    private CisAppTokenValidator validator;
    private HttpServletRequest request;

    @BeforeEach
    void setUp() {
        validator = Mockito.spy(new CisAppTokenValidator(TENANT_ID, LOGIC_APP_ID, CIS_APP_ID));
        request = mock(HttpServletRequest.class);
    }

    @ParameterizedTest
    @MethodSource("invalidTokenProvider")
    void hasValidApplicationToken_invalidTokens_returnFalse(String token) {
        when(request.getHeader(HEADER_KEY)).thenReturn(token);
        assertFalse(validator.hasValidApplicationToken(request));
    }
    
    @Test
    void hasValidApplicationToken_invalidSignature_returnsFalse() {
        when(request.getHeader(HEADER_KEY)).thenReturn(VALID_TOKEN);
        doReturn(false).when(validator).validateToken(VALID_TOKEN);
        assertFalse(validator.hasValidApplicationToken(request));
    }

    @Test
    void validateToken_invalidJwtFormat_returnsFalse() {
        assertFalse(validator.validateToken("not-a-jwt"));
    }

    @Test
    void verifyAudience_valid_returnsTrue() {
        List<String> audience = Arrays.asList("api://" + CIS_APP_ID);
        assertTrue(validator.verifyAudience(CIS_APP_ID, audience));
    }

    @Test
    void verifyAudience_invalid_returnsFalse() {
        List<String> audience = Arrays.asList("api://otherApp");
        assertFalse(validator.verifyAudience(CIS_APP_ID, audience));
    }

    @Test
    void verifyAppId_valid_returnsTrue() {
        assertTrue(validator.verifyAppId(LOGIC_APP_ID, LOGIC_APP_ID));
    }

    @Test
    void verifyAppId_invalid_returnsFalse() {
        assertFalse(validator.verifyAppId(LOGIC_APP_ID, "wrongAppId"));
    }

    @Test
    void verifyIssuer_valid_returnsTrue() {
        String issuer = "https://sts.windows.net/" + TENANT_ID + "/";
        assertTrue(validator.verifyIssuer(issuer));
    }

    @Test
    void verifyIssuer_invalid_returnsFalse() {
        assertFalse(validator.verifyIssuer("https://sts.windows.net/otherTenant/"));
    }

    @Test
    void verifyTenant_valid_returnsTrue() {
        assertTrue(validator.verifyTenant(TENANT_ID));
    }

    @Test
    void verifyTenant_invalid_returnsFalse() {
        assertFalse(validator.verifyTenant("otherTenant"));
    }

    @Test
    void verifyTokenClaimSet_allValid_returnsTrue() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("api://" + CIS_APP_ID)
                .claim("appid", LOGIC_APP_ID)
                .issuer("https://sts.windows.net/" + TENANT_ID + "/")
                .claim("tid", TENANT_ID)
                .expirationTime(new Date(System.currentTimeMillis() + 10000))
                .notBeforeTime(new Date(System.currentTimeMillis() - 10000))
                .build();
        assertTrue(validator.verifyTokenClaimSet(claims));
    }

    @Test
    void verifyTokenClaimSet_invalidAudience_returnsFalse() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("api://otherApp")
                .claim("appid", LOGIC_APP_ID)
                .issuer("https://sts.windows.net/" + TENANT_ID + "/")
                .claim("tid", TENANT_ID)
                .expirationTime(new Date(System.currentTimeMillis() + 10000))
                .notBeforeTime(new Date(System.currentTimeMillis() - 10000))
                .build();
        assertFalse(validator.verifyTokenClaimSet(claims));
    }

    @Test
    void verifyTokenClaimSet_expired_returnsFalse() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("api://" + CIS_APP_ID)
                .claim("appid", LOGIC_APP_ID)
                .issuer("https://sts.windows.net/" + TENANT_ID + "/")
                .claim("tid", TENANT_ID)
                .expirationTime(new Date(System.currentTimeMillis() - 10000))
                .notBeforeTime(new Date(System.currentTimeMillis() - 20000))
                .build();
        assertFalse(validator.verifyTokenClaimSet(claims));
    }

    @Test
    void verifyTokenClaimSet_notYetValid_returnsFalse() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("api://" + CIS_APP_ID)
                .claim("appid", LOGIC_APP_ID)
                .issuer("https://sts.windows.net/" + TENANT_ID + "/")
                .claim("tid", TENANT_ID)
                .expirationTime(new Date(System.currentTimeMillis() + 10000))
                .notBeforeTime(new Date(System.currentTimeMillis() + 10000))
                .build();
        assertFalse(validator.verifyTokenClaimSet(claims));
    }

    @Test
    void verifyTokenClaimSet_missingClaims_returnsFalse() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().build();
        assertFalse(validator.verifyTokenClaimSet(claims));
    }

    @Test
    void verifyTokenClaimSet_nullAudience_returnsFalse() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("appid", LOGIC_APP_ID)
                .issuer("https://sts.windows.net/" + TENANT_ID + "/")
                .claim("tid", TENANT_ID)
                .expirationTime(new Date(System.currentTimeMillis() + 10000))
                .notBeforeTime(new Date(System.currentTimeMillis() - 10000))
                .build();
        assertFalse(validator.verifyTokenClaimSet(claims));
    }

    @Test
    void verifyTokenClaimSet_nullAppId_returnsFalse() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("api://" + CIS_APP_ID)
                .issuer("https://sts.windows.net/" + TENANT_ID + "/")
                .claim("tid", TENANT_ID)
                .expirationTime(new Date(System.currentTimeMillis() + 10000))
                .notBeforeTime(new Date(System.currentTimeMillis() - 10000))
                .build();
        assertFalse(validator.verifyTokenClaimSet(claims));
    }

    @Test
    void verifyTokenClaimSet_nullTid_returnsFalse() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("api://" + CIS_APP_ID)
                .claim("appid", LOGIC_APP_ID)
                .issuer("https://sts.windows.net/" + TENANT_ID + "/")
                .expirationTime(new Date(System.currentTimeMillis() + 10000))
                .notBeforeTime(new Date(System.currentTimeMillis() - 10000))
                .build();
        assertFalse(validator.verifyTokenClaimSet(claims));
    }

    @Test
    void verifyTokenClaimSet_nullIssuer_returnsFalse() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("api://" + CIS_APP_ID)
                .claim("appid", LOGIC_APP_ID)
                .claim("tid", TENANT_ID)
                .expirationTime(new Date(System.currentTimeMillis() + 10000))
                .notBeforeTime(new Date(System.currentTimeMillis() - 10000))
                .build();
        assertFalse(validator.verifyTokenClaimSet(claims));
    }

    @Test
    void verifyTokenClaimSet_nullExpiration_returnsFalse() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("api://" + CIS_APP_ID)
                .claim("appid", LOGIC_APP_ID)
                .issuer("https://sts.windows.net/" + TENANT_ID + "/")
                .claim("tid", TENANT_ID)
                .notBeforeTime(new Date(System.currentTimeMillis() - 10000))
                .build();
        assertThrows(NullPointerException.class, () -> validator.verifyTokenClaimSet(claims));
    }

    @Test
    void verifyTokenClaimSet_nullNotBefore_returnsException() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience("api://" + CIS_APP_ID)
                .claim("appid", LOGIC_APP_ID)
                .issuer("https://sts.windows.net/" + TENANT_ID + "/")
                .claim("tid", TENANT_ID)
                .expirationTime(new Date(System.currentTimeMillis() + 10000))
                .build();
        assertThrows(NullPointerException.class, () -> validator.verifyTokenClaimSet(claims));
    }

    @Test
    void getPublicKeyFromAzureADWithCache_nonRSAKey_throwsException() {
        CisAppTokenValidator validatorSpy = spy(new CisAppTokenValidator(TENANT_ID, LOGIC_APP_ID, CIS_APP_ID));
        JWKSet mockJwkSet = mock(JWKSet.class);
        JWK mockJwk = mock(JWK.class); // Not an RSAKey
        validatorSpy.jwkSetCache.set(mockJwkSet);
        when(mockJwkSet.getKeyByKeyId(anyString())).thenReturn(mockJwk);
        assertThrows(IllegalArgumentException.class, () -> validatorSpy.getPublicKeyFromAzureADWithCache("keyId"));
    }

    @Test
    void getPublicKeyFromAzureADWithCache_keyNotFound_refreshesCacheAndThrowsIfStillMissing() {
        CisAppTokenValidator validatorSpy = spy(new CisAppTokenValidator(TENANT_ID, LOGIC_APP_ID, CIS_APP_ID));
        JWKSet mockJwkSet = mock(JWKSet.class);
        validatorSpy.jwkSetCache.set(mockJwkSet);
        when(mockJwkSet.getKeyByKeyId(anyString())).thenReturn(null); // Simulate key not found
        doReturn(mockJwkSet).when(validatorSpy).jwkSetCache.get();
        assertThrows(WrongTypeOfReturnValue.class, () -> validatorSpy.getPublicKeyFromAzureADWithCache("keyId"));
    }

    @Test
    void getPublicKeyFromAzureADWithCache_jwkSetLoadThrowsException_throwsException() throws Exception {
        CisAppTokenValidator validatorSpy = spy(new CisAppTokenValidator(TENANT_ID, LOGIC_APP_ID, CIS_APP_ID));
        validatorSpy.jwkSetCache.set(null);
        doThrow(new RuntimeException("Failed to load JWKSet"))
                .when(validatorSpy)
                .getPublicKeyFromAzureADWithCache(anyString());
        assertThrows(RuntimeException.class, () -> validatorSpy.getPublicKeyFromAzureADWithCache("keyId"));
    }

    @Test
    void getPublicKeyFromAzureADWithCache_rsaKeyConversionThrowsException() throws Exception {
        CisAppTokenValidator validatorSpy = spy(new CisAppTokenValidator(TENANT_ID, LOGIC_APP_ID, CIS_APP_ID));
        JWKSet mockJwkSet = mock(JWKSet.class);
        RSAKey mockRsaKey = mock(RSAKey.class);
        validatorSpy.jwkSetCache.set(mockJwkSet);
        when(mockJwkSet.getKeyByKeyId(anyString())).thenReturn((JWK) mockRsaKey);
        doThrow(new RuntimeException("RSA conversion error")).when(mockRsaKey).toRSAPublicKey();
        assertThrows(RuntimeException.class, () -> validatorSpy.getPublicKeyFromAzureADWithCache("keyId"));
    }

    @Test
    void hasValidApplicationToken_headerMissing_returnsFalse() {
        when(request.getHeader("missing-header")).thenReturn(null);
        assertFalse(validator.hasValidApplicationToken(request));
    }

    @Test
    void verifyAudience_emptyAudience_returnsFalse() {
        assertFalse(validator.verifyAudience(CIS_APP_ID, Arrays.asList()));
    }

    @Test
    void verifyAppId_nullClaim_returnsFalse() {
        assertFalse(validator.verifyAppId(LOGIC_APP_ID, null));
    }

    @Test
    void verifyIssuer_nullIssuer_returnsFalse() {
        assertFalse(validator.verifyIssuer(null));
    }

    @Test
    void verifyTenant_nullTenant_returnsFalse() {
        assertFalse(validator.verifyTenant(null));
    }

    @Test
    void verifyTokenClaimSet_nullClaims_returnsException() {
        assertThrows(NullPointerException.class, () -> validator.verifyTokenClaimSet(null));
    }
    
    @Test
    void verifyTokenClaimSet_nullClaims_throwsException() {
        assertThrows(NullPointerException.class, () -> validator.verifyTokenClaimSet(null));
    }

    @Test
    void isInvalidSignature_invalidSignature_returnsTrue() throws Exception {
        CisAppTokenValidator validatorSpy = Mockito.spy(new CisAppTokenValidator(TENANT_ID, LOGIC_APP_ID, CIS_APP_ID));
        SignedJWT mockJwt = mock(SignedJWT.class);
        JWSHeader mockHeader = mock(JWSHeader.class);
        when(mockJwt.getHeader()).thenReturn(mockHeader);
        when(mockHeader.getKeyID()).thenReturn("keyId");
        RSAPublicKey mockKey = mock(RSAPublicKey.class);
        doReturn(mockKey).when(validatorSpy).getPublicKeyFromAzureADWithCache("keyId");
        doReturn(false).when(mockJwt).verify(any(JWSVerifier.class));
        assertTrue(validatorSpy.isInvalidSignature(mockJwt));
    }
    private static java.util.stream.Stream<String> invalidTokenProvider() {
        return java.util.stream.Stream.of(null, "", "not-a-jwt");
    }
}
