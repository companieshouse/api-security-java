package uk.gov.companieshouse.api.interceptor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;

/**
 * <p>A general-purpose mapping of {@code String} keys to {@code Set<String>} values intended to
 * represent permissions tokens.</p>
 * Uses a fluent builder pattern to simplify instantiation.
 * <ul>
 *   <li>A default mapping is <b>required</b>. Start with:</li>
 *   <ul>
 *     <li>{@code defaultAllOf(String ...)} to map any key non-specific keys to a non-empty set
 *     of values, or</li>
 *     <li>{@code defaultNone()} to map any non-specific keys to an empty values set.
 *   </ul>
 *   <li>and then explicit mappings are <b>optional</b>:</li>
 *   <ul>
 *       <li>Use {@code mapAllOf(String, String ...)} to set a mapping for the given key to a
 *       non-empty set of values.</li>
 *       <li>Use {@code mapNone()} to set a mapping for the given key to an empty values set.</li>
 *   </ul>
 * </ul>
 * <p>
 * Examples:
 * <ol>
 *     <li>Create a mapping
 *       <ul>
 *           <li>(default) &rarr; ["read"]</li>
 *       </ul>
 *         {@code PermissionMapping.builder().defaultAllOf("read").build()}</li>
 *     <li>Create a mapping
 *       <ul>
 *           <li>(default) &rarr; [ ]</li>
 *           <li>"POST" &rarr; [ "readprotected", "create" ]</li>
 *       </ul>
 *         {@code PermissionMapping.builder().defaultNone().mapAllOf("POST",
 *     "readprotected", "create").build()}</li>
 *     <li>Create a mapping
 *       <ul>
 *           <li>(default) &rarr; [ "read" ]</li>
 *           <li>"GET" &rarr; [ ]</li>
 *           <li>"POST" &rarr; [ "readprotected", "create" ]</li>
 *       </ul>
 *         {@code PermissionMapping.builder().defaultAllOf("read").mapAllOf("POST",
 *     "readprotected", "create").mapNone("GET").build()}</li>
 * </ol>
 */
public class PermissionsMapping implements PermissionsAllowable {
    private static final String DEFAULT_KEY = null;

    /* Internal value representing an empty (size 0) value set. Used here because
    HashSetValuedHashMap does not add a mapping for if the values set is empty.
     */
    private static final String EMPTY_VALUE = null;

    private final HashSetValuedHashMap<String, String> permissionsMap;


    @Override
    public Set<String> apply(final String key) {
        final Set<String> storedValues =
                permissionsMap.get(permissionsMap.containsKey(key) ? key : DEFAULT_KEY);

        return storedValues.contains(EMPTY_VALUE)
                ? Collections.emptySet()
                : Collections.unmodifiableSet(storedValues);
    }

    private PermissionsMapping() {
        permissionsMap = new HashSetValuedHashMap<>();
    }

    public static PermissionsDefaultBuilder builder() {
        return new PermissionsMappingBuilder();
    }

    public static class PermissionsMappingBuilder
            implements PermissionsDefaultBuilder, PermissionsMapBuilder {
        private final List<Consumer<PermissionsMapping>> buildSteps;

        private PermissionsMappingBuilder() {
            this.buildSteps = new ArrayList<>();
        }

        @Override
        public PermissionsMappingBuilder defaultAllOf(final String... values) {
            buildSteps.add(
                    p -> p.permissionsMap.putAll(DEFAULT_KEY, buildImmutableNonEmptySet(values)));
            return this;
        }

        @Override
        public PermissionsMappingBuilder defaultNone() {
            buildSteps.add(
                    p -> p.permissionsMap.putAll(DEFAULT_KEY, Collections.singleton(EMPTY_VALUE)));
            return this;
        }

        @Override
        public PermissionsMappingBuilder mapAllOf(final String key, final String... values) {
            buildSteps.add(p -> p.permissionsMap.putAll(key, buildImmutableNonEmptySet(values)));
            return this;
        }

        @Override
        public PermissionsMappingBuilder mapNone(final String key) {
            buildSteps.add(p -> p.permissionsMap.putAll(key, Collections.singleton(EMPTY_VALUE)));
            return this;
        }

        public PermissionsMapping build() {
            final PermissionsMapping mapping = new PermissionsMapping();

            buildSteps.forEach(step -> step.accept(mapping));

            return mapping;
        }

        private static Set<String> buildImmutableNonEmptySet(final String[] values) {
            Objects.requireNonNull(values, "<values> must not be null");
            if (values.length == 0) {
                throw new IllegalArgumentException("<values> must not be empty");
            }
            if (Arrays.stream(values).anyMatch(Objects::isNull)) {
                throw new IllegalArgumentException("<values> must not contain a null");
            }

            return Collections.unmodifiableSet(Arrays.stream(values).collect(Collectors.toSet()));
        }

    }

}
