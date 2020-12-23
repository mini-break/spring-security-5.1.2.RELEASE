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
package org.springframework.security.config.annotation.authentication.configuration;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.aop.framework.ProxyFactoryBean;
import org.springframework.aop.target.LazyInitTargetSource;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.JdbcUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.configuration.ObjectPostProcessorConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

/**
 * 1.这里首先构建了一个 AuthenticationManagerBuilder 实例，
 * 这个实例就是用来构建全局 AuthenticationManager 的 AuthenticationManagerBuilder，
 * 具体的构建过程在下面的 getAuthenticationManager 方法中。
 * 不过这里的这个全局的 AuthenticationManagerBuilder 并非总是有用，为什么这么说呢？且看下面的的分析。
 *
 * 2.另外还有一些 initializeXXX 方法，用来构建全局的 UserDetailService 和 AuthenticationProvider，
 * 这些方法小伙伴可以作为一个了解，因为正常情况下是不会用到这几个 Bean 的，
 * 只有当 getAuthenticationManager 方法被调用时，这些默认的 Bean 才会被配置，
 * 而 getAuthenticationManager 方法被调用，意味着我们要使用系统默认配置的 AuthenticationManager 作为 parent，
 * 而在实际使用中，我们一般不会使用系统默认配置的 AuthenticationManager 作为 parent，我们自己多多少少都会重新定制一下。
 *
 * Exports the authentication {@link Configuration}
 *
 * @author Rob Winch
 * @since 3.2
 *
 */
@Configuration
@Import(ObjectPostProcessorConfiguration.class)
public class AuthenticationConfiguration {

	/**
	 * 标志位，AuthenticationManager 是否正处于构建过程中
	 */
	private AtomicBoolean buildingAuthenticationManager = new AtomicBoolean();

	private ApplicationContext applicationContext;

	/**
	 * 用于记录所要构建的 AuthenticationManager 
	 */
	private AuthenticationManager authenticationManager;

	/**
	 * authenticationManagerInitialized 是 authenticationManager 是否已经被构建的标志，
	 * 如果 authenticationManager 已经被构建，则 authenticationManagerInitialized 为 true，
	 * 否则为 false
	 */
	private boolean authenticationManagerInitialized;

	private List<GlobalAuthenticationConfigurerAdapter> globalAuthConfigurers = Collections
			.emptyList();

	private ObjectPostProcessor<Object> objectPostProcessor;

	/**
	 * 定义一个bean，认证管理器构建器  AuthenticationManagerBuilder，
	 * 该构建器最终被用于构建AuthenticationManager 对象
	 */
	@Bean
	public AuthenticationManagerBuilder authenticationManagerBuilder(
			ObjectPostProcessor<Object> objectPostProcessor, ApplicationContext context) {
		/**
		 * Lazy 密码加密器 ： 该对象创建时容器中可能还不存在真正的密码加密器，
		 * 但是用该 lazy密码加密器进行加密或者密码匹配时，会从容器中获取类型为 PasswordEncoder 的密码加密器,
		 * 如果容器中不存在类型为 PasswordEncoder 的密码加密器,
		 * 则使用PasswordEncoderFactories.createDelegatingPasswordEncoder() 创建一个 PasswordEncoder
		 * 供随后加密或者密码匹配使用
		 * LazyPasswordEncoder 是定义在当前配置类中的一个内部类
		 */
		LazyPasswordEncoder defaultPasswordEncoder = new LazyPasswordEncoder(context);
		AuthenticationEventPublisher authenticationEventPublisher = getBeanOrNull(context, AuthenticationEventPublisher.class);

		/**
		 * 生成  AuthenticationManagerBuilder 实例，使用实现类为 DefaultPasswordEncoderAuthenticationManagerBuilder,
		 * DefaultPasswordEncoderAuthenticationManagerBuilder 是定义在该配置类中的一个内部类, 它继承自
		 * AuthenticationManagerBuilder， 是 Spring Security 缺省使用的 AuthenticationManagerBuilder 实现类,
		 * 它限定了密码加密器使用上面定义的 LazyPasswordEncoder defaultPasswordEncoder
		 */
		DefaultPasswordEncoderAuthenticationManagerBuilder result = new DefaultPasswordEncoderAuthenticationManagerBuilder(objectPostProcessor, defaultPasswordEncoder);
		if (authenticationEventPublisher != null) {
			result.authenticationEventPublisher(authenticationEventPublisher);
		}
		return result;
	}

	/**
	 * 定义一个类型为 GlobalAuthenticationConfigurerAdapter  的 bean ,
	 * 名称 : enableGlobalAuthenticationAutowiredConfigurer
	 * 实现类型 : AuthenticationConfiguration$EnableGlobalAuthenticationAutowiredConfigurer
	 * 目的 : 1. 触发使用了注解@EnableGlobalAuthentication的bean的构建过程,
	 *       2. 如果是调试模式，则输出一条日志 : Eagerly initializing XXX
	 */
	@Bean
	public static GlobalAuthenticationConfigurerAdapter enableGlobalAuthenticationAutowiredConfigurer(
			ApplicationContext context) {
		return new EnableGlobalAuthenticationAutowiredConfigurer(context);
	}

	/**
	 * 定义一个类型为 GlobalAuthenticationConfigurerAdapter  的 bean ,
	 * 名称 : initializeUserDetailsBeanManagerConfigurer
	 * 实现类型 : InitializeUserDetailsBeanManagerConfigurer
	 * 目的 : 为 AuthenticationManagerBuilder 添加一个 InitializeUserDetailsManagerConfigurer 配置器，
	 * InitializeUserDetailsManagerConfigurer 会在容器中没有用于构建 AuthenticationManager 的
	 * AuthenticationProvider bean,也没有为 AuthenticationManagerBuilder 设置 parent AuthenticationManager 时,
	 * 尝试使用容器中类型为 UserDetailsService 的bean构造一个 DaoAuthenticationProvider 并设置到
	 * AuthenticationManagerBuilder 上， 当然，如果容器中连 UserDetailsService bean 也不存在，则
	 * InitializeUserDetailsManagerConfigurer 什么都不做直接返回。
	 * InitializeUserDetailsManagerConfigurer 构建 DaoAuthenticationProvider 时，如果容器中存在
	 * PasswordEncoder , UserDetailsPasswordService 也会将它们应用到 DaoAuthenticationProvider 
	 */
	@Bean
	public static InitializeUserDetailsBeanManagerConfigurer initializeUserDetailsBeanManagerConfigurer(ApplicationContext context) {
		return new InitializeUserDetailsBeanManagerConfigurer(context);
	}

	/**
	 * 定义一个类型为 GlobalAuthenticationConfigurerAdapter  的 bean ,
	 * 名称 : initializeAuthenticationProviderBeanManagerConfigurer
	 * 实现类型 : InitializeAuthenticationProviderBeanManagerConfigurer
	 * 目的 : 为 AuthenticationManagerBuilder 设置 authenticationProvider， 所设置的
	 * AuthenticationProvider 来自容器中类型为 AuthenticationProvider 的一个 bean,
	 * 注意： 虽然 AuthenticationManagerBuilder 可以接受多个 AuthenticationProvider，
	 * 但这里 InitializeAuthenticationProviderBeanManagerConfigurer 只会从容器中获得
	 * 一个 AuthenticationProvider(如果有多个 AuthenticationProvider，则会返回 null,而不是采用第一个)
	 */
	@Bean
	public static InitializeAuthenticationProviderBeanManagerConfigurer initializeAuthenticationProviderBeanManagerConfigurer(ApplicationContext context) {
		return new InitializeAuthenticationProviderBeanManagerConfigurer(context);
	}

	/**
	 * 根据配置生成认证管理器 AuthenticationManager
	 * 1. 具备幂等性
	 * 2. 并且进行了同步处理
	 * 首次调用会触发真正的构建过程生成认证管理器 AuthenticationManager，
	 * 再次的调用都会返回首次构建的认证管理器 AuthenticationManager
	 */
	public AuthenticationManager getAuthenticationManager() throws Exception {
		if (this.authenticationManagerInitialized) {
			return this.authenticationManager;
		}
		AuthenticationManagerBuilder authBuilder = authenticationManagerBuilder(
				this.objectPostProcessor, this.applicationContext);
		/**
		 * 标志位 buildingAuthenticationManager 表示是否正在使用 authBuilder 进行构建
		 * true 表示现在正在构建过程中， false 表示现在不在构建过程中
		 * 下面的 getAndSet(true) 调用总是会
		 * 1. 返回 buildingAuthenticationManager 之前的值
		 * 2. 将 buildingAuthenticationManager 设置为 true
		 */
		if (this.buildingAuthenticationManager.getAndSet(true)) {
			// 如果已经正在使用 authBuilder 进行构建, 则这里直接返回一个包装了
			// 构建器 authBuilder 的 AuthenticationManagerDelegator 对象
			return new AuthenticationManagerDelegator(authBuilder);
		}

		/**
		 * 在  authBuilder 上应用全局认证配置器,
		 * 这里所谓的"应用" 其实只是将 GlobalAuthenticationConfigurerAdapter 设置到
		 * authBuilder,它们最终会在 authBuilder.build() 过程中会被真正使用
		 */
		for (GlobalAuthenticationConfigurerAdapter config : globalAuthConfigurers) {
			authBuilder.apply(config);
		}

		/**
		 * 构建器 authBuilder 执行构建，生成认证管理器 authenticationManager，
		 * 具体的构建过程，可以参考 ：
		 * 1. AbstractSecurityBuilder#build
		 * 2. AbstractConfiguredSecurityBuilder#doBuild
		 * 这里 AbstractConfiguredSecurityBuilder 继承自 AbstractSecurityBuilder
		 */
		authenticationManager = authBuilder.build();

		/**
		 * 如果容器中没有用于构建 AuthenticationManager 的 AuthenticationProvider bean
		 * 供 authBuilder 使用,也没有为 authBuilder 设置 parent AuthenticationManager 时,
		 * 则上面产生的 authenticationManager 为 null 。 不过这种情况缺省情况下并不会发生,
		 * 因为该配置类中 bean InitializeUserDetailsBeanManagerConfigurer 为 authBuilder
		 * 添加的 InitializeUserDetailsBeanManagerConfigurer 会在这种情况下构造一个
		 * DaoAuthenticationProvider 对象给 authBuilder 使用。另外，一般情况下，开发人员也会
		 * 提供自己的 AuthenticationProvider 实现类。
		 *
		 * 通常经过上面的 authBuilder.build()，authenticationManager 对象都会被创建,
		 * 但是如果 authenticationManager 未被创建，这里尝试使用 getAuthenticationManagerBean()
		 * 再次设置 authenticationManager
		 */
		if (authenticationManager == null) {
			// getAuthenticationManagerBean() 其实是返回一个实现了接口 AuthenticationManager
			// 的代理对象 , 通过 ProxyFactoryBean 对象工厂创建该代理对象
			authenticationManager = getAuthenticationManagerBean();
		}

		// authenticationManager 构建完成，将标志 authenticationManagerInitialized 设置为 true
		this.authenticationManagerInitialized = true;
		return authenticationManager;
	}

	/**
	 * 可选设置全局认证配置器，这里指的全局认证配置器类型为 GlobalAuthenticationConfigurerAdapter，
	 * 缺省为当前配置类定义的三个 GlobalAuthenticationConfigurerAdapter :
	 * 实现类型分别为 :
	 * AuthenticationConfiguration$EnableGlobalAuthenticationAutowiredConfigurer
	 * InitializeAuthenticationProviderBeanManagerConfigurer
	 * InitializeUserDetailsBeanManagerConfigurer
	 */
	@Autowired(required = false)
	public void setGlobalAuthenticationConfigurers(
			List<GlobalAuthenticationConfigurerAdapter> configurers) throws Exception {
		Collections.sort(configurers, AnnotationAwareOrderComparator.INSTANCE);
		this.globalAuthConfigurers = configurers;
	}

	@Autowired
	public void setApplicationContext(ApplicationContext applicationContext) {
		this.applicationContext = applicationContext;
	}

	@Autowired
	public void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
		this.objectPostProcessor = objectPostProcessor;
	}

	// 创建实现了指定接口 interfaceName 的代理对象
	@SuppressWarnings("unchecked")
	private <T> T lazyBean(Class<T> interfaceName) {
		LazyInitTargetSource lazyTargetSource = new LazyInitTargetSource();
		String[] beanNamesForType = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(
				applicationContext, interfaceName);
		if (beanNamesForType.length == 0) {
			return null;
		}
		Assert.isTrue(beanNamesForType.length == 1,
				() -> "Expecting to only find a single bean for type " + interfaceName
						+ ", but found " + Arrays.asList(beanNamesForType));
		lazyTargetSource.setTargetBeanName(beanNamesForType[0]);
		lazyTargetSource.setBeanFactory(applicationContext);
		ProxyFactoryBean proxyFactory = new ProxyFactoryBean();
		proxyFactory = objectPostProcessor.postProcess(proxyFactory);
		proxyFactory.setTargetSource(lazyTargetSource);
		return (T) proxyFactory.getObject();
	}

	// 创建 AuthenticationManager 代理对象
	private AuthenticationManager getAuthenticationManagerBean() {
		return lazyBean(AuthenticationManager.class);
	}

	// 从容器中获取指定类型为 type 的bean，如果没找到则返回 null
	private static <T> T getBeanOrNull(ApplicationContext applicationContext, Class<T> type) {
		try {
			return applicationContext.getBean(type);
		} catch(NoSuchBeanDefinitionException notFound) {
			return null;
		}
	}

	// 没有什么实质性内容
	private static class EnableGlobalAuthenticationAutowiredConfigurer extends
			GlobalAuthenticationConfigurerAdapter {
		private final ApplicationContext context;
		private static final Log logger = LogFactory
				.getLog(EnableGlobalAuthenticationAutowiredConfigurer.class);

		public EnableGlobalAuthenticationAutowiredConfigurer(ApplicationContext context) {
			this.context = context;
		}

		@Override
		public void init(AuthenticationManagerBuilder auth) {
			Map<String, Object> beansWithAnnotation = context
					.getBeansWithAnnotation(EnableGlobalAuthentication.class);
			if (logger.isDebugEnabled()) {
				logger.debug("Eagerly initializing " + beansWithAnnotation);
			}
		}
	}

	/**
	 * Prevents infinite recursion in the event that initializing the
	 * AuthenticationManager.
	 *
	 * @author Rob Winch
	 * @since 4.1.1
	 */
	static final class AuthenticationManagerDelegator implements AuthenticationManager {
		private AuthenticationManagerBuilder delegateBuilder;
		private AuthenticationManager delegate;
		private final Object delegateMonitor = new Object();

		AuthenticationManagerDelegator(AuthenticationManagerBuilder delegateBuilder) {
			Assert.notNull(delegateBuilder, "delegateBuilder cannot be null");
			this.delegateBuilder = delegateBuilder;
		}

		@Override
		public Authentication authenticate(Authentication authentication)
				throws AuthenticationException {
			if (this.delegate != null) {
				return this.delegate.authenticate(authentication);
			}

			synchronized (this.delegateMonitor) {
				if (this.delegate == null) {
					this.delegate = this.delegateBuilder.getObject();
					this.delegateBuilder = null;
				}
			}

			return this.delegate.authenticate(authentication);
		}

		@Override
		public String toString() {
			return "AuthenticationManagerDelegator [delegate=" + this.delegate + "]";
		}
	}

	static class DefaultPasswordEncoderAuthenticationManagerBuilder extends AuthenticationManagerBuilder {
		private PasswordEncoder defaultPasswordEncoder;

		/**
		 * Creates a new instance
		 *
		 * @param objectPostProcessor the {@link ObjectPostProcessor} instance to use.
		 */
		DefaultPasswordEncoderAuthenticationManagerBuilder(
			ObjectPostProcessor<Object> objectPostProcessor, PasswordEncoder defaultPasswordEncoder) {
			super(objectPostProcessor);
			this.defaultPasswordEncoder = defaultPasswordEncoder;
		}

		@Override
		public InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> inMemoryAuthentication()
			throws Exception {
			return super.inMemoryAuthentication()
				.passwordEncoder(this.defaultPasswordEncoder);
		}

		@Override
		public JdbcUserDetailsManagerConfigurer<AuthenticationManagerBuilder> jdbcAuthentication()
			throws Exception {
			return super.jdbcAuthentication()
				.passwordEncoder(this.defaultPasswordEncoder);
		}

		@Override
		public <T extends UserDetailsService> DaoAuthenticationConfigurer<AuthenticationManagerBuilder, T> userDetailsService(
			T userDetailsService) throws Exception {
			return super.userDetailsService(userDetailsService)
				.passwordEncoder(this.defaultPasswordEncoder);
		}
	}

	static class LazyPasswordEncoder implements PasswordEncoder {
		private ApplicationContext applicationContext;
		private PasswordEncoder passwordEncoder;

		LazyPasswordEncoder(ApplicationContext applicationContext) {
			this.applicationContext = applicationContext;
		}

		@Override
		public String encode(CharSequence rawPassword) {
			return getPasswordEncoder().encode(rawPassword);
		}

		@Override
		public boolean matches(CharSequence rawPassword,
			String encodedPassword) {
			return getPasswordEncoder().matches(rawPassword, encodedPassword);
		}

		@Override
		public boolean upgradeEncoding(String encodedPassword) {
			return getPasswordEncoder().upgradeEncoding(encodedPassword);
		}

		private PasswordEncoder getPasswordEncoder() {
			if (this.passwordEncoder != null) {
				return this.passwordEncoder;
			}
			PasswordEncoder passwordEncoder = getBeanOrNull(this.applicationContext, PasswordEncoder.class);
			if (passwordEncoder == null) {
				passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
			}
			this.passwordEncoder = passwordEncoder;
			return passwordEncoder;
		}

		@Override
		public String toString() {
			return getPasswordEncoder().toString();
		}
	}
}
