package org.apache.shiro.spring.boot.kisso.realm;

import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.kisso.KissoTokenPrincipal;
import org.apache.shiro.spring.boot.kisso.token.KissoToken;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * Kisso Stateless AuthorizingRealm
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public class KissoStatelessAuthorizingRealm extends AbstractAuthorizingRealm<KissoTokenPrincipal> {

	@Override
	public Class<?> getAuthenticationTokenClass() {
		return KissoToken.class;// 此Realm只支持KissoToken
	}
	
	/*
	 * 授权,JWT已包含访问主张只需要解析其中的主张定义就行了
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		
		KissoTokenPrincipal principal = (KissoTokenPrincipal) principals.getPrimaryPrincipal();
		
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		// 解析角色并设置
		info.setRoles(principal.getRoles());
		// 解析权限并设置
		info.setStringPermissions(principal.getPerms());
		return info;
	}
	
}
