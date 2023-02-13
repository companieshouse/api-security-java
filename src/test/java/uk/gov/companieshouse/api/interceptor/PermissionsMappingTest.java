package uk.gov.companieshouse.api.interceptor;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsEmptyCollection.empty;
import static org.hamcrest.collection.IsIterableContainingInAnyOrder.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class PermissionsMappingTest {
    private PermissionsMapping testMapping;

    @Test
    void builderWhenDefaultNone() {
        testMapping = PermissionsMapping.builder().defaultRequireNone()
                .build();

        assertThat(testMapping.apply("POST"), is(empty()));

    }

    @Test
    void builderWhenDefaultNoneAndRequiredAllOfEmpty() {
        final PermissionsMapping.PermissionsMappingBuilder builder =
                PermissionsMapping.builder().defaultRequireAnyOf();

        assertThrows(IllegalArgumentException.class, builder::build);

    }

    @Test
    void builderWhenDefaultContainsOnlyNull() {
        final PermissionsMapping.PermissionsMappingBuilder builder =
                PermissionsMapping.builder().defaultRequireAnyOf((String) null);

        assertThrows(IllegalArgumentException.class, builder::build);

    }

    @Test
    void builderWhenDefaultContainsNull() {
        final PermissionsMapping.PermissionsMappingBuilder builder =
                PermissionsMapping.builder().defaultRequireAnyOf(null, "read");

        assertThrows(IllegalArgumentException.class, builder::build);

    }

    @Test
    void builderWhenDefaultNull() {
        final PermissionsMapping.PermissionsMappingBuilder builder =
                PermissionsMapping.builder().defaultRequireAnyOf((String[]) null);

        assertThrows(NullPointerException.class, builder::build);
    }

    @Test
    void builderWhenDefaultOnly() {
        testMapping = PermissionsMapping.builder().defaultRequireAnyOf("readprotected", "read")
                .build();

        assertThat(testMapping.apply("GET"), containsInAnyOrder("readprotected", "read"));
        assertThat(testMapping.apply("POST"), containsInAnyOrder("readprotected", "read"));
    }

    @Test
    void builderWhenDefaultAllAndRequiredAll() {
        testMapping = PermissionsMapping.builder()
                .defaultRequireAnyOf("readprotected", "read")
                .mappedRequireAnyOf("POST", "create")
                .build();

        assertThat(testMapping.apply("GET"), containsInAnyOrder("readprotected", "read"));
        assertThat(testMapping.apply("POST"), containsInAnyOrder("create"));
    }

    @Test
    void builderWhenDefaultAllAndRequiredNone() {
        testMapping = PermissionsMapping.builder()
                .defaultRequireAnyOf("readprotected", "read")
                .mappedRequireNone("POST")
                .build();

        assertThat(testMapping.apply("GET"), containsInAnyOrder("readprotected", "read"));
        assertThat(testMapping.apply("POST"), is(empty()));
    }

    @Test
    void builderWhenDefaultAllAndRequiredEmpty() {
        final PermissionsMapping.PermissionsMappingBuilder builder = PermissionsMapping.builder()
                .defaultRequireAnyOf("readprotected", "read")
                .mappedRequireAnyOf("POST");

        assertThrows(IllegalArgumentException.class, builder::build);
    }

    @Test
    void builderWhenDefaultAllAndRequiredNull() {
        final PermissionsMapping.PermissionsMappingBuilder builder = PermissionsMapping.builder()
                .defaultRequireAnyOf("readprotected", "read")
                .mappedRequireAnyOf("POST", (String[]) null);

        assertThrows(NullPointerException.class, builder::build);
    }

    @Test
    void builderWhenDefaultAllAndRequiredContainsOnlyNull() {
        final PermissionsMapping.PermissionsMappingBuilder builder = PermissionsMapping.builder()
                .defaultRequireAnyOf("readprotected", "read")
                .mappedRequireAnyOf("POST", (String) null);

        assertThrows(IllegalArgumentException.class, builder::build);
    }

    @Test
    void builderWhenDefaultAllAndRequiredContainsNull() {
        final PermissionsMapping.PermissionsMappingBuilder builder =
                PermissionsMapping.builder()
                        .defaultRequireAnyOf("readprotected", "read")
                        .mappedRequireAnyOf("POST", null, "read");

        assertThrows(IllegalArgumentException.class, builder::build);
    }

}