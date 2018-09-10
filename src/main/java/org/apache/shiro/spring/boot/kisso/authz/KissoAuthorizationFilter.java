package org.apache.shiro.spring.boot.kisso.authz;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authz.AbstracAuthorizationFilter;
import org.apache.shiro.spring.boot.kisso.exception.URIUnpermittedException;
import org.apache.shiro.spring.boot.kisso.token.KissoAccessToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.baomidou.kisso.SSOAuthorization;
import com.baomidou.kisso.SSOConfig;
import com.baomidou.kisso.SSOHelper;
import com.baomidou.kisso.common.auth.AuthDefaultImpl;
import com.baomidou.kisso.security.token.SSOToken;

/**
 * Kisso 授权 (authorization) 过滤器
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public class KissoAuthorizationFilter extends AbstracAuthorizationFilter {

	private static final Logger LOG = LoggerFactory.getLogger(KissoAuthorizationFilter.class);
	/*
     * 系统权限授权接口
     */
    private SSOAuthorization authorization = new AuthDefaultImpl();
    
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		
		try {
			
			// Step 1、 获取当前请求 Kisso Token
			SSOToken token = SSOHelper.getSSOToken(WebUtils.toHttp(request));
	        if (token == null) {
	            return false;
	        }
	        
			/*
	         * Step 2、URL 权限认证
			 */
	        if (SSOConfig.getInstance().isPermissionUri()) {
	            String uri = WebUtils.toHttp(request).getRequestURI();
	            if (!(uri == null || this.getAuthorization().isPermitted(token, uri))) {
	            	throw new URIUnpermittedException("URI Unpermitted Access.");
	            }
	        }
	        
	        // Step 3、生成Token 
			AuthenticationToken actoken = new KissoAccessToken(getHost(request), token);
			
			// Step 4、委托给Realm进行登录  
			Subject subject = getSubject(request, response);
			subject.login(actoken);
	        
			// Step 5、执行授权成功后的函数
			return onAccessSuccess(mappedValue, subject, request, response);
		} catch (AuthenticationException e) {
			//Step 6、执行授权失败后的函数
			return onAccessFailure(mappedValue, e, request, response);
		} 
	}
	
	/**
	 * TODO
	 * @author ：<a href="https://github.com/vindell">vindell</a>
	 * @param mappedValue
	 * @param e
	 * @param request
	 * @param response
	 * @return
	 */
	@Override
	protected boolean onAccessFailure(Object mappedValue, Exception e, ServletRequest request,
			ServletResponse response) throws IOException {

		LOG.error("Host {} Kisso Authentication Failure : {}", getHost(request), e.getMessage());
		
		HttpServletRequest httpRequest = WebUtils.toHttp(request);
		HttpServletResponse httpResponse = WebUtils.toHttp(response);
		
		String mString = "Attempting to access a path which requires authentication. ";
		if (LOG.isTraceEnabled()) { 
			LOG.trace(mString);
		} 
		
		// 响应异常状态信息
		Map<String, Object> data = new HashMap<String, Object>();
		data.put("status", "fail");
		// URI验证失败
		if (e instanceof URIUnpermittedException) {
			data.put("message", "URI Unpermitted Access.");
		} else {
			data.put("message", mString);
		}
		
		if (WebUtils.isAjaxRequest(httpRequest)) {
			/* AJAX 请求 403 未授权访问提示 */
			httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
			WebUtils.writeJSONString(httpResponse, data);
        } else {
        	// If subject is known but not authorized, redirect to the unauthorized URL if
			// there is one
			// If no unauthorized URL is specified, just return an unauthorized HTTP status
			// code
			String unauthorizedUrl = getUnauthorizedUrl();
			// SHIRO-142 - ensure that redirect _or_ error code occurs - both cannot happen
			// due to response commit:
			if (StringUtils.hasText(unauthorizedUrl)) {
				WebUtils.issueRedirect(request, response, unauthorizedUrl);
			} else {
				WebUtils.toHttp(response).sendError(HttpServletResponse.SC_UNAUTHORIZED, "Forbidden");
			}
        }
	 
		return false;
	}

	public SSOAuthorization getAuthorization() {
		return authorization;
	}

	public void setAuthorization(SSOAuthorization authorization) {
		this.authorization = authorization;
	}
	
}
