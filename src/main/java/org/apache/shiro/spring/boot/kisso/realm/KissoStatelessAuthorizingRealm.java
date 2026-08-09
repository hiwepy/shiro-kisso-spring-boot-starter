package org.apache.shiro.spring.boot.kisso.realm;

import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.biz.realm.AbstractAuthorizingRealm;
import org.apache.shiro.spring.boot.kisso.KissoStatelessPrincipal;
import org.apache.shiro.spring.boot.kisso.token.KissoAccessToken;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * Shiro authorizing realm for Kisso stateless (token-based) authentication.
 * <p>Supports {@link KissoAccessToken} instances and extracts roles and permissions
 * from the JWT claims embedded in the SSO token.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class KissoStatelessAuthorizingRealm extends AbstractAuthorizingRealm {

	@Override
	public Class<? extends AuthenticationToken> getAuthenticationTokenClass() {
		return KissoAccessToken.class;// 此Realm只支持KissoAccessToken
	}
	
	/*
	 * 授权,JWT已包含访问主张只需要解析其中的主张定义就行了
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		
		KissoStatelessPrincipal principal = (KissoStatelessPrincipal) principals.getPrimaryPrincipal();
		
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		// 解析角色并设置
		Optional.ofNullable(principal.getRoles()).ifPresent(roles -> {
			info.setRoles(roles.stream().map(role -> role.getKey()).collect(Collectors.toSet()));
		});
		// 解析权限并设置
		info.setStringPermissions(principal.getPerms());
		return info;
	}
	
}
