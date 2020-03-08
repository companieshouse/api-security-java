package uk.gov.companieshouse.api.util.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class AuthorisationUtilTest {

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
    void getTokenPermissionsMissingObject() {
        Optional<TokenPermissions> result = AuthorisationUtil.getTokenPermissions(request);

        assertFalse(result.isPresent());
    }
}
