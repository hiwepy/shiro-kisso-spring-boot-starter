package org.apache.shiro.spring.boot.kisso.realm;

import org.apache.shiro.spring.boot.kisso.token.KissoLoginToken;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link KissoStatefulAuthorizingRealm}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("KissoStatefulAuthorizingRealm Tests")
class KissoStatefulAuthorizingRealmTest {

    @Test
    @DisplayName("Instance can be created")
    void testInstantiation() {
        KissoStatefulAuthorizingRealm realm = new KissoStatefulAuthorizingRealm();
        assertThat(realm).isNotNull();
    }

    @Test
    @DisplayName("getAuthenticationTokenClass returns KissoLoginToken")
    void testGetAuthenticationTokenClass() {
        KissoStatefulAuthorizingRealm realm = new KissoStatefulAuthorizingRealm();
        assertThat(realm.getAuthenticationTokenClass()).isEqualTo(KissoLoginToken.class);
    }
}
