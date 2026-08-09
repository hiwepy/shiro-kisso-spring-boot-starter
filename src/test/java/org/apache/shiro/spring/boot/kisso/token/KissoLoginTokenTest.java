package org.apache.shiro.spring.boot.kisso.token;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link KissoLoginToken}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("KissoLoginToken Tests")
class KissoLoginTokenTest {

    @Test
    @DisplayName("Default constructor creates instance")
    void testDefaultConstructor() {
        KissoLoginToken token = new KissoLoginToken();
        assertThat(token).isNotNull();
    }
}
