/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.config.annotation.web.configuration;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;

import org.springframework.beans.factory.BeanClassLoaderAware;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.ImportAware;
import org.springframework.core.OrderComparator;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.annotation.Order;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.context.DelegatingApplicationListener;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;


/**
 * Spring Web Security 的配置类 :
 *  1. 使用一个 WebSecurity 对象基于安全配置创建一个 FilterChainProxy 对象来对用户请求进行安全过滤。
 *  2. 也会暴露一些必要的 bean。
 *  3. 如何定制 Spring security 的web 安全，也就是 WebSecurity 对象
 *    3.1 实现一个继承自 WebSecurityConfigurerAdapter 的配置类 ,
 *    3.2 或者 提供一个配置类，实现了接口 WebSecurityConfigurer
 *    该配置类的配置会在使用 @EnableWebSecurity 时应用到系统。
 *
 * Uses a {@link WebSecurity} to create the {@link FilterChainProxy} that performs the web
 * based security for Spring Security. It then exports the necessary beans. Customizations
 * can be made to {@link WebSecurity} by extending {@link WebSecurityConfigurerAdapter}
 * and exposing it as a {@link Configuration} or implementing
 * {@link WebSecurityConfigurer} and exposing it as a {@link Configuration}. This
 * configuration is imported when using {@link EnableWebSecurity}.
 *
 * @see EnableWebSecurity
 * @see WebSecurity
 *
 * @author Rob Winch
 * @author Keesun Baik
 * @since 3.2
 */
@Configuration
public class WebSecurityConfiguration implements ImportAware, BeanClassLoaderAware {
	/**
	 * 使用一个WebSecurity对象基于用户指定的或者默认的安全配置，创建一个FilterChainProxy bean来对用户请求进行安全过滤。
	 * 这个FilterChainProxy bean的名称为springSecurityFilterChain,它也是一个Filter，
	 * 最终会被作为Servlet过滤器链中的一个Filter应用到Servlet容器中
	 */
	private WebSecurity webSecurity;

	/**
	 * 是否启用了调试模式，来自注解 @EnableWebSecurity 的属性 debug，缺省值 false
	 */
	private Boolean debugEnabled;

	/**
	 * 获取容器中所有WebSecurityConfigurer类型
	 */
	private List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers;

	private ClassLoader beanClassLoader;

	@Autowired(required = false)
	private ObjectPostProcessor<Object> objectObjectPostProcessor;

	@Bean
	public static DelegatingApplicationListener delegatingApplicationListener() {
		return new DelegatingApplicationListener();
	}

	/**
	 * 定义一个bean，是表达式处理器，缺省为一个 DefaultWebSecurityExpressionHandler，
	 * 仅在 bean springSecurityFilterChain 实例化之后才能实例化
	 */
	@Bean
	@DependsOn(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public SecurityExpressionHandler<FilterInvocation> webSecurityExpressionHandler() {
		return webSecurity.getExpressionHandler();
	}

	/**
	 * 创建过滤器链(FilterChainProxy)的方法
	 * Creates the Spring Security Filter Chain
	 * @return the {@link Filter} that represents the security filter chain
	 * @throws Exception
	 */
	@Bean(name = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public Filter springSecurityFilterChain() throws Exception {
		boolean hasConfigurers = webSecurityConfigurers != null
				&& !webSecurityConfigurers.isEmpty();
		if (!hasConfigurers) {
			/**
			 * 如果没有配置类的话, 就导入一个默认的配置类
			 * 所以当我们只在pom文件导入security依赖的时候, 也会默认执行弹窗验证的原因
			 */
			WebSecurityConfigurerAdapter adapter = objectObjectPostProcessor
					.postProcess(new WebSecurityConfigurerAdapter() {
					});
			webSecurity.apply(adapter);
		}
		/**
		 * WebSecurity#build()会返回一个过滤器链(FilterChainProxy)
		 * 根据配置 webSecurityConfigurers或者缺省 WebSecurityConfigurerAdapter 构建
		 * Filter FilterChainProxy 并返回，这是最终加入到Servlet容器的Filter chain
		 * 中的一个 Filter, 但实际上，它的内部也维护了一个自己的安全相关的 Filter chain
		 */
		return webSecurity.build();
	}

	/**
	 * 定义一个bean，是web调用权限评估器，用于判断一个用户是否可以访问某个URL，
	 * 对于 JSP tag 支持必要。 仅在bean springSecurityFilterChain 被定义时才生效。
	 *
	 * Creates the {@link WebInvocationPrivilegeEvaluator} that is necessary for the JSP
	 * tag support.
	 * @return the {@link WebInvocationPrivilegeEvaluator}
	 * @throws Exception
	 */
	@Bean
	@DependsOn(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public WebInvocationPrivilegeEvaluator privilegeEvaluator() throws Exception {
		return webSecurity.getPrivilegeEvaluator();
	}

	/**
	 * 用于创建web configuration的SecurityConfigurer实例，
	 * 注意该参数通过@Value(...)方式注入
	 *
	 * 这个方法里面设置和排序 webSecurityConfigurers
	 * WebSecurityConfigurerAdapter 继承 WebSecurityConfigurer<WebSecurity>,
	 * 这里就是在扫描自定义的配置类, 并且按照 @Order 排序之后, 依次装入WebSecurity里面, 用于webSecurity.build();
	 * 看下面代码知道, 我们的配置类可以写很多个, 但是 @Order 设置的大小不能重复
	 *
	 * Sets the {@code <SecurityConfigurer<FilterChainProxy, WebSecurityBuilder>}
	 * instances used to create the web configuration.
	 *
	 * @param objectPostProcessor the {@link ObjectPostProcessor} used to create a
	 * {@link WebSecurity} instance
	 * @param webSecurityConfigurers the
	 * {@code <SecurityConfigurer<FilterChainProxy, WebSecurityBuilder>} instances used to
	 * create the web configuration
	 * @throws Exception
	 */
	@Autowired(required = false) // @Autowired注解，方法会在程序启动时执行一遍
	public void setFilterChainProxySecurityConfigurer(
			ObjectPostProcessor<Object> objectPostProcessor,
			@Value("#{@autowiredWebSecurityConfigurersIgnoreParents.getWebSecurityConfigurers()}") List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers)
			throws Exception {
		/**
		 * 创建并初始化 webSecurity
		 * 将WebSecurity交由IOC容器管理
 		 */
		webSecurity = objectPostProcessor
				.postProcess(new WebSecurity(objectPostProcessor));
		if (debugEnabled != null) {
			webSecurity.debug(debugEnabled);
		}

		// 使用 AnnotationAwareOrderComparator规则, 对所有的 webSecurityConfigurer 进行排序
		Collections.sort(webSecurityConfigurers, AnnotationAwareOrderComparator.INSTANCE);

		Integer previousOrder = null;
		Object previousConfig = null;
		// 校验SecurityConfigurer Order配置
		for (SecurityConfigurer<Filter, WebSecurity> config : webSecurityConfigurers) {
			Integer order = AnnotationAwareOrderComparator.lookupOrder(config);
			// 校验Order
			if (previousOrder != null && previousOrder.equals(order)) {
				throw new IllegalStateException(
						"@Order on WebSecurityConfigurers must be unique. Order of "
								+ order + " was already used on " + previousConfig + ", so it cannot be used on "
								+ config + " too.");
			}
			previousOrder = order;
			previousConfig = config;
		}
		// 依次将webSecurityConfigurer加入到 webSecurity 里面
		for (SecurityConfigurer<Filter, WebSecurity> webSecurityConfigurer : webSecurityConfigurers) {
			// 自定义的WebSecurityConfigurerAdapter也会加入WebSecurity(AbstractConfiguredSecurityBuilder中configurers集合)
			webSecurity.apply(webSecurityConfigurer);
		}
		// 设置 webSecurityConfigurers
		this.webSecurityConfigurers = webSecurityConfigurers;
	}

	/**
	 * 定义一个bean,类型为AutowiredWebSecurityConfigurersIgnoreParents，其作用为从Spring容器中
	 * 获取所有类型为WebSecurityConfigurer的bean，这些bean就是要应用的安全配置原料
	 */
	@Bean
	public static AutowiredWebSecurityConfigurersIgnoreParents autowiredWebSecurityConfigurersIgnoreParents(
			ConfigurableListableBeanFactory beanFactory) {
		return new AutowiredWebSecurityConfigurersIgnoreParents(beanFactory);
	}

	/**
	 * A custom verision of the Spring provided AnnotationAwareOrderComparator that uses
	 * {@link AnnotationUtils#findAnnotation(Class, Class)} to look on super class
	 * instances for the {@link Order} annotation.
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	private static class AnnotationAwareOrderComparator extends OrderComparator {
		private static final AnnotationAwareOrderComparator INSTANCE = new AnnotationAwareOrderComparator();

		@Override
		protected int getOrder(Object obj) {
			return lookupOrder(obj);
		}

		private static int lookupOrder(Object obj) {
			if (obj instanceof Ordered) {
				return ((Ordered) obj).getOrder();
			}
			if (obj != null) {
				Class<?> clazz = (obj instanceof Class ? (Class<?>) obj : obj.getClass());
				Order order = AnnotationUtils.findAnnotation(clazz, Order.class);
				if (order != null) {
					return order.value();
				}
			}
			return Ordered.LOWEST_PRECEDENCE;
		}
	}

	/*
	 * 获取导入该配置bean的配置bean上的注解元数据并设置到该配置bean
     * 这里主要是为了获取注解 @EnableWebSecurity 的属性 debugEnabled
	 * (non-Javadoc)
	 *
	 * @see org.springframework.context.annotation.ImportAware#setImportMetadata(org.
	 * springframework.core.type.AnnotationMetadata)
	 */
	public void setImportMetadata(AnnotationMetadata importMetadata) {
		Map<String, Object> enableWebSecurityAttrMap = importMetadata
				.getAnnotationAttributes(EnableWebSecurity.class.getName());
		AnnotationAttributes enableWebSecurityAttrs = AnnotationAttributes
				.fromMap(enableWebSecurityAttrMap);
		debugEnabled = enableWebSecurityAttrs.getBoolean("debug");
		if (webSecurity != null) {
			webSecurity.debug(debugEnabled);
		}
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see
	 * org.springframework.beans.factory.BeanClassLoaderAware#setBeanClassLoader(java.
	 * lang.ClassLoader)
	 */
	public void setBeanClassLoader(ClassLoader classLoader) {
		this.beanClassLoader = classLoader;
	}
}
