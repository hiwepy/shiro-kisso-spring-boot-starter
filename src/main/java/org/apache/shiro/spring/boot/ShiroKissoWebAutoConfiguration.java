package org.apache.shiro.spring.boot;

import org.apache.shiro.spring.boot.kisso.KissoStatelessPrincipalRepository;
import org.apache.shiro.spring.web.config.AbstractShiroWebConfiguration;
import org.springframework.beans.BeansException;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.baomidou.kisso.SSOAuthorization;
import com.baomidou.kisso.common.auth.AuthDefaultImpl;
import com.baomidou.kisso.starter.KissoAutoConfiguration;
import com.baomidou.kisso.web.handler.KissoDefaultHandler;
import com.baomidou.kisso.web.handler.SSOHandlerInterceptor;

/**
 * Auto-configuration for Shiro Kisso web integration.
 * <p>Registers Kisso-specific beans for SSO authorization, handler interceptor,
 * and principal repository. Activated only when {@code shiro.kisso.enabled=true}.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 * @see <a href="https://gitee.com/baomidou/kisso">Kisso Documentation</a>
 */
@Configuration
@AutoConfigureBefore( name = {
	"org.apache.shiro.spring.config.web.autoconfigure.ShiroWebAutoConfiguration",  // shiro-spring-boot-web-starter
	"org.apache.shiro.spring.boot.ShiroBizWebAutoConfiguration" // spring-boot-starter-shiro-biz
})
@ConditionalOnProperty(prefix = ShiroKissoProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ ShiroKissoProperties.class })
@ImportAutoConfiguration(KissoAutoConfiguration.class)
public class ShiroKissoWebAutoConfiguration extends AbstractShiroWebConfiguration implements ApplicationContextAware {

	private ApplicationContext applicationContext;
	
	/**
	 * Creates a {@link SSOAuthorization} if no existing bean is present.
	 *
	 * @return the default SSO authorization implementation
	 */
	@Bean
	@ConditionalOnMissingBean
	public SSOAuthorization kissoAuthorization() {
		return new AuthDefaultImpl();
	}

	/**
	 * Creates a {@link SSOHandlerInterceptor} if no existing bean is present.
	 *
	 * @return the default Kisso handler interceptor
	 */
	@Bean
	@ConditionalOnMissingBean
	public SSOHandlerInterceptor kissoHandlerInterceptor() {
		return new KissoDefaultHandler();
	}

	/**
	 * Creates a {@link KissoStatelessPrincipalRepository} if no existing bean is present.
	 *
	 * @return the Kisso principal repository
	 */
	@Bean
	@ConditionalOnMissingBean
	public KissoStatelessPrincipalRepository kissoPrincipalRepository() {
		return new KissoStatelessPrincipalRepository();
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}

}
