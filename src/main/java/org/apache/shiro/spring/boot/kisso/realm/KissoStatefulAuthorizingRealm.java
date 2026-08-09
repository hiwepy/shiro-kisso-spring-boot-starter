package org.apache.shiro.spring.boot.kisso.realm;

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.kisso.token.KissoLoginToken;

/**
 * Shiro authorizing realm for Kisso stateful (cookie-based) authentication.
 * <p>Supports {@link KissoLoginToken} instances for stateful SSO login flows.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class KissoStatefulAuthorizingRealm extends AbstractAuthorizingRealm {

	@Override
	public Class<? extends AuthenticationToken> getAuthenticationTokenClass() {
		return KissoLoginToken.class;// 此Realm只支持KissoLoginToken
	}

}
