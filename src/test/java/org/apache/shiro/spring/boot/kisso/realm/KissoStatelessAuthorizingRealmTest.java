package org.apache.shiro.spring.boot.kisso.realm;

import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.spring.boot.kisso.KissoStatelessPrincipal;
import org.apache.shiro.spring.boot.kisso.token.KissoAccessToken;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.baomidou.kisso.security.token.SSOToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link KissoStatelessAuthorizingRealm}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("KissoStatelessAuthorizingRealm Tests")
class KissoStatelessAuthorizingRealmTest {

    @Test
    @DisplayName("Instance can be created")
    void testInstantiation() {
        KissoStatelessAuthorizingRealm realm = new KissoStatelessAuthorizingRealm();
        assertThat(realm).isNotNull();
    }

    @Test
    @DisplayName("getAuthenticationTokenClass returns KissoAccessToken")
    void testGetAuthenticationTokenClass() {
        KissoStatelessAuthorizingRealm realm = new KissoStatelessAuthorizingRealm();
        assertThat(realm.getAuthenticationTokenClass()).isEqualTo(KissoAccessToken.class);
    }

    @Test
    @DisplayName("doGetAuthorizationInfo returns authorization info")
    void testDoGetAuthorizationInfo() {
        KissoStatelessAuthorizingRealm realm = new KissoStatelessAuthorizingRealm();

        SSOToken ssoToken = mock(SSOToken.class);
        when(ssoToken.getId()).thenReturn("user123");
        when(ssoToken.getClaims()).thenReturn(new io.jsonwebtoken.impl.DefaultClaims());

        KissoStatelessPrincipal principal = new KissoStatelessPrincipal(ssoToken);
        principal.setUserid("user123");
        principal.setPerms(java.util.Collections.singleton("read"));

        PrincipalCollection principals = new SimplePrincipalCollection(principal, "realm");
        AuthorizationInfo info = realm.doGetAuthorizationInfo(principals);
        assertThat(info).isNotNull();
    }
}
