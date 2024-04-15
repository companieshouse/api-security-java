package uk.gov.companieshouse.api.interceptor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;

import jakarta.servlet.http.HttpServletResponse;
import uk.gov.companieshouse.api.util.security.EricConstants;
import uk.gov.companieshouse.api.util.security.SecurityConstants;

@ExtendWith(MockitoExtension.class)
@TestInstance(Lifecycle.PER_CLASS)
class RoleInterceptorTest {
    
    private static final Object NO_HANDLER = null;
    
    private MockHttpServletRequest mockRequest = new MockHttpServletRequest();

    @Mock
    private HttpServletResponse mockResponse;
    
    private RoleInterceptor roleInterceptor;
    
    @BeforeEach
    void setup() {
        roleInterceptor = new RoleInterceptor("/admin/search");
        mockRequest = new MockHttpServletRequest();
    }

    @Test
    @DisplayName("Test the Handler allows a user with the correct set of permissions, roles & priviledges through")
    public void testUserWithCorrectPriviledges() throws IOException {

        mockRequest.addHeader(EricConstants.ERIC_IDENTITY, "test data");
        mockRequest.addHeader(EricConstants.ERIC_IDENTITY_TYPE, "oauth2");
        mockRequest.addHeader(EricConstants.ERIC_AUTHORISED_ROLES, "/admin/roles /admin/search /admin/user/search");
        mockRequest.addHeader(EricConstants.ERIC_AUTHORISED_KEY_ROLES,SecurityConstants.INTERNAL_USER_ROLE);
        assertTrue(roleInterceptor.preHandle(mockRequest, mockResponse, NO_HANDLER));
    }

    @Test
    @DisplayName("Test the Handler stops a user without /admin/search role")
    public void testUserWithNoAdminSearchRole() throws IOException {
        mockRequest.addHeader(EricConstants.ERIC_IDENTITY, "test data");
        mockRequest.addHeader(EricConstants.ERIC_IDENTITY_TYPE, "oauth2");
        mockRequest.addHeader(EricConstants.ERIC_AUTHORISED_ROLES, "/admin/roles /admin/user/search");
        mockRequest.addHeader(EricConstants.ERIC_AUTHORISED_KEY_ROLES,SecurityConstants.INTERNAL_USER_ROLE);
        assertFalse(roleInterceptor.preHandle(mockRequest, mockResponse, NO_HANDLER));
    }
}
