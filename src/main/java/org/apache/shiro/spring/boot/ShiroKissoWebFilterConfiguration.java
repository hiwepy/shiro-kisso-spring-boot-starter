package org.apache.shiro.spring.boot;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Configuration;


/**
 * Filter configuration for Shiro Kisso web integration.
 * <p>Registers Kisso-specific filters into the Shiro filter chain.
 * Activated only when {@code shiro.kisso.enabled=true}.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 * @see <a href="https://gitee.com/baomidou/kisso">Kisso Documentation</a>
 */
@Configuration
@AutoConfigureBefore( name = {
	"org.apache.shiro.spring.config.web.autoconfigure.ShiroWebFilterConfiguration",  // shiro-spring-boot-web-starter
	"org.apache.shiro.spring.boot.ShiroBizWebFilterConfiguration" // spring-boot-starter-shiro-biz
})
/**
 * <p>Configuration properties.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@ConditionalOnProperty(prefix = ShiroKissoProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ ShiroKissoProperties.class })
public class ShiroKissoWebFilterConfiguration implements ApplicationContextAware {

	protected static final Logger LOG = LoggerFactory.getLogger(ShiroKissoWebFilterConfiguration.class);
	private ApplicationContext applicationContext;
	
	
	
	@Override
	/**
	 * Sets the application context.
	 *
	 * @param applicationContext the application context
	 * @throws BeansException if an error occurs
	 */
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	/**
	 * Returns the application context.
	 *
	 * @return the application context
	 */
	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}

}
