package org.apache.shiro.spring.boot.kisso.realm;

import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.kisso.KissoTokenPrincipal;
import org.apache.shiro.spring.boot.kisso.token.KissoToken;

/**
 * Kisso Stateful AuthorizingRealm
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class KissoStatefulAuthorizingRealm extends AbstractAuthorizingRealm<KissoTokenPrincipal> {

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return KissoToken.class;// 此Realm只支持KissoToken
	}

}
