package org.apache.shiro.spring.boot.kisso.token;

import com.baomidou.kisso.security.token.SSOToken;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link KissoAccessToken}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("KissoAccessToken Tests")
class KissoAccessTokenTest {

    @Test
    @DisplayName("Constructor sets all fields correctly")
    void testConstructor() {
        SSOToken ssoToken = mock(SSOToken.class);
        KissoAccessToken token = new KissoAccessToken("192.168.1.1", ssoToken);
        assertThat(token.getHost()).isEqualTo("192.168.1.1");
        assertThat(token.getToken()).isSameAs(ssoToken);
        assertThat(token.getPrincipal()).isSameAs(ssoToken);
        assertThat(token.getCredentials()).isSameAs(ssoToken);
    }
}
