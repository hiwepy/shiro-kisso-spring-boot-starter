package org.apache.shiro.spring.boot.kisso.authz;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link KissoPermissionAnnotationMethodInterceptor}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("KissoPermissionAnnotationMethodInterceptor Tests")
class KissoPermissionAnnotationMethodInterceptorTest {

    @Test
    @DisplayName("Default constructor creates instance")
    void testDefaultConstructor() {
        KissoPermissionAnnotationMethodInterceptor interceptor = new KissoPermissionAnnotationMethodInterceptor();
        assertThat(interceptor).isNotNull();
    }
}
