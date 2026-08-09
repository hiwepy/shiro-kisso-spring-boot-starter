package org.apache.shiro.spring.boot.kisso;

import com.baomidou.kisso.security.token.SSOToken;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link KissoStatelessPrincipal}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("KissoStatelessPrincipal Tests")
class KissoStatelessPrincipalTest {

    @Test
    @DisplayName("Constructor sets token correctly")
    void testConstructor() {
        SSOToken ssoToken = mock(SSOToken.class);
        KissoStatelessPrincipal principal = new KissoStatelessPrincipal(ssoToken);
        assertThat(principal).isNotNull();
        assertThat(principal.getToken()).isSameAs(ssoToken);
    }
}
