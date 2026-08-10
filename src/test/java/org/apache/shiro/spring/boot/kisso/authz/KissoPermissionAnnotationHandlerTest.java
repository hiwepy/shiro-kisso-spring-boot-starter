package org.apache.shiro.spring.boot.kisso.authz;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link KissoPermissionAnnotationHandler}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("KissoPermissionAnnotationHandler Tests")
class KissoPermissionAnnotationHandlerTest {

    @Test
    @DisplayName("Instance can be created")
    void testInstantiation() {
        KissoPermissionAnnotationHandler handler = new KissoPermissionAnnotationHandler();
        assertThat(handler).isNotNull();
    }
}
