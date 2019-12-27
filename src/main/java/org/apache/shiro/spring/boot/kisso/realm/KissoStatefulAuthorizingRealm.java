package org.apache.shiro.spring.boot.kisso.realm;

import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.kisso.token.KissoLoginToken;

/**
 * Kisso Stateful AuthorizingRealm
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class KissoStatefulAuthorizingRealm extends AbstractAuthorizingRealm {

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return KissoLoginToken.class;// 此Realm只支持KissoLoginToken
	}

}
