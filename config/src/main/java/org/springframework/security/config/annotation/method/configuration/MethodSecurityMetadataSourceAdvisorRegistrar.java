/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.method.configuration;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityMetadataSourceAdvisor;
import org.springframework.util.MultiValueMap;

/**
 * 这个类会向Spring容器注册一个MethodSecurityMetadataSourceAdvisor
 * 
 * Creates Spring Security's MethodSecurityMetadataSourceAdvisor only when
 * using proxy based method security (i.e. do not do it when using ASPECTJ).
 * The conditional logic is controlled through {@link GlobalMethodSecuritySelector}.
 *
 * @author Rob Winch
 * @since 4.0.2
 * @see GlobalMethodSecuritySelector
 */
class MethodSecurityMetadataSourceAdvisorRegistrar implements
		ImportBeanDefinitionRegistrar {

	/**
	 * Register, escalate, and configure the AspectJ auto proxy creator based on the value
	 * of the @{@link EnableGlobalMethodSecurity#proxyTargetClass()} attribute on the
	 * importing {@code @Configuration} class.
	 */
	@Override
	public void registerBeanDefinitions(AnnotationMetadata importingClassMetadata,
			BeanDefinitionRegistry registry) {

		BeanDefinitionBuilder advisor = BeanDefinitionBuilder
				.rootBeanDefinition(MethodSecurityMetadataSourceAdvisor.class);
		advisor.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
		// 定义3个构建函数参数
		advisor.addConstructorArgValue("methodSecurityInterceptor");// 一个拦截器的bean name
		advisor.addConstructorArgReference("methodSecurityMetadataSource");// Spring容器定义的bean
		advisor.addConstructorArgValue("methodSecurityMetadataSource");

		/**
		 * 获取@EnableGlobalMethodSecurity注解中的所属值
		 * importingClassMetadata为含有@EnableGlobalMethodSecurity注解的类
		 */
		MultiValueMap<String, Object> attributes = importingClassMetadata.getAllAnnotationAttributes(EnableGlobalMethodSecurity.class.getName());
		Integer order = (Integer) attributes.getFirst("order");
		if (order != null) {
			advisor.addPropertyValue("order", order);
		}

		registry.registerBeanDefinition("metaDataSourceAdvisor",
				advisor.getBeanDefinition());
	}
}
