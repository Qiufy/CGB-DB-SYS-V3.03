package com.cy.pj.common.config;
import java.util.LinkedHashMap;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SpringShiroConfig {
	
	
   
	/**
	 * 配置SecurityManager对象(shiro核心安全管理器对象)
	 */
	@Bean
	public SecurityManager securityManager(
			Realm realm) {
		DefaultWebSecurityManager sManager=
		new DefaultWebSecurityManager();
		sManager.setRealm(realm);
		return sManager;
	}
	/**
	 * 配置ShiroFilterFactoryBean对象，通过此对象
	 * 创建过滤器工厂，并指定过滤规则
	 * @param securityManager
	 * @return
	 */
	@Bean
	public ShiroFilterFactoryBean shiroFilterFactory (
			SecurityManager securityManager) {
		ShiroFilterFactoryBean sfBean=
				new ShiroFilterFactoryBean();
		sfBean.setSecurityManager(securityManager);
		sfBean.setLoginUrl("/doLoginUI");
		//定义map指定请求过滤规则(哪些资源允许匿名访问,哪些必须认证访问)
		LinkedHashMap<String,String> map=
				new LinkedHashMap<>();
		//静态资源允许匿名访问:"anon"
		map.put("/bower_components/**","anon");
		map.put("/build/**","anon");
		map.put("/dist/**","anon");
		map.put("/plugins/**","anon");
		map.put("/user/doLogin", "anon");
		map.put("/doLogout","logout");
		//除了匿名访问的资源,其它都要认证("authc")后访问
		map.put("/**","authc");
		sfBean.setFilterChainDefinitionMap(map);
		return sfBean;
	}
}
