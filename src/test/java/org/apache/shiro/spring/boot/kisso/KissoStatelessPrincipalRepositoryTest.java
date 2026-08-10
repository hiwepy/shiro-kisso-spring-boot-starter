package org.apache.shiro.spring.boot.kisso;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link KissoStatelessPrincipalRepository}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("KissoStatelessPrincipalRepository Tests")
class KissoStatelessPrincipalRepositoryTest {

    @Test
    @DisplayName("Instance can be created")
    void testInstantiation() {
        KissoStatelessPrincipalRepository repo = new KissoStatelessPrincipalRepository();
        assertThat(repo).isNotNull();
    }
}
