package uk.gov.companieshouse.api.util.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;

@ExtendWith(MockitoExtension.class)
class AuthorisationUtilTest {

    @Mock
    HttpServletRequest request;

    @Test
    void getTokenPermissionsValidObject() {
        TokenPermissions tokenPermissions = Mockito.mock(TokenPermissions.class);
        when(request.getAttribute("token_permissions")).thenReturn(tokenPermissions);

        Optional<TokenPermissions> result = AuthorisationUtil.getTokenPermissions(request);

        assertTrue(result.isPresent());
        assertEquals(tokenPermissions, result.get());
    }

    @Test
    void getTokenPermissionsInvalidObject() {
        when(request.getAttribute("token_permissions")).thenReturn(new Object());

        Optional<TokenPermissions> result = AuthorisationUtil.getTokenPermissions(request);

        assertFalse(result.isPresent());
    }

    @Test
    void getTokenPermissionsMissingObject() {
        Optional<TokenPermissions> result = AuthorisationUtil.getTokenPermissions(request);

        assertFalse(result.isPresent());
    }

    @Test
    void isOauth2UserRequiredFields(){
        MockHttpServletRequest httpServletRequest = new MockHttpServletRequest();
        httpServletRequest.addHeader(EricConstants.ERIC_IDENTITY, "*");
        httpServletRequest.addHeader(EricConstants.ERIC_IDENTITY_TYPE, "oauth2");
        
        assertTrue(AuthorisationUtil.isOauth2User(httpServletRequest));
    }

    @Test
    void isOauth2UserKeyIdentityType(){
        MockHttpServletRequest httpServletRequest = new MockHttpServletRequest();
        httpServletRequest.addHeader(EricConstants.ERIC_IDENTITY, "*");
        httpServletRequest.addHeader(EricConstants.ERIC_IDENTITY_TYPE, "key");
    
        assertFalse(AuthorisationUtil.isOauth2User(httpServletRequest));
    }   

    @Test
    void isOauth2UserIdentityTypeNotSet(){
        MockHttpServletRequest httpServletRequest = new MockHttpServletRequest();
        httpServletRequest.addHeader(EricConstants.ERIC_IDENTITY_TYPE, "key");
    
        assertFalse(AuthorisationUtil.isOauth2User(httpServletRequest));
    }      
}