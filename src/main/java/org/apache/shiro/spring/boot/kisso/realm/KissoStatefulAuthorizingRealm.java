package org.apache.shiro.spring.boot.kisso.realm;

import org.apache.shiro.biz.authz.principal.ShiroPrincipal;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.kisso.token.KissoLoginToken;

/**
 * Kisso Stateful AuthorizingRealm
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class KissoStatefulAuthorizingRealm extends AbstractAuthorizingRealm<ShiroPrincipal> {

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return KissoLoginToken.class;// 此Realm只支持KissoLoginToken
	}

}
