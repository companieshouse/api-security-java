package uk.gov.companieshouse.api.util.security;

public class InvalidTokenPermissionException extends Exception {

    private static final long serialVersionUID = -7263125402151395706L;

    private final String authorisedTokenPermissions;

    public InvalidTokenPermissionException(String authorisedTokenPermissions) {
        this.authorisedTokenPermissions = authorisedTokenPermissions;
    }

    public String getAuthorisedTokenPermissions() {
        return authorisedTokenPermissions;
    }

    @Override
    public String getMessage() {
        return "Invalid token permission header: " + getAuthorisedTokenPermissions();
    }
}
