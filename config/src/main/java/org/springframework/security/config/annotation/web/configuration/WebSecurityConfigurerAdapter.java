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
package org.springframework.security.config.annotation.web.configuration;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.aop.TargetSource;
import org.springframework.aop.framework.Advised;
import org.springframework.aop.target.LazyInitTargetSource;
import org.springframework.beans.FatalBeanException;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.JdbcUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

/**
 * WebSecurityConfigurerAdapter是Spring Security Config内置提供的一个WebSecurityConfigurer抽象实现类。
 * WebSecurityConfigurerAdapter存在的目的是提供一个方便开发人员配置WebSecurity的基类。它提供了一组全方位配置WebSecurity的缺省方法实现
 *
 * Provides a convenient base class for creating a {@link WebSecurityConfigurer}
 * instance. The implementation allows customization by overriding methods.
 *
 * <p>
 * Will automatically apply the result of looking up
 * {@link AbstractHttpConfigurer} from {@link SpringFactoriesLoader} to allow
 * developers to extend the defaults.
 * To do this, you must create a class that extends AbstractHttpConfigurer and then create a file in the classpath at "META-INF/spring.factories" that looks something like:
 * </p>
 * <pre>
 * org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer = sample.MyClassThatExtendsAbstractHttpConfigurer
 * </pre>
 * If you have multiple classes that should be added you can use "," to separate the values. For example:
 *
 * <pre>
 * org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer = sample.MyClassThatExtendsAbstractHttpConfigurer, sample.OtherThatExtendsAbstractHttpConfigurer
 * </pre>
 *
 * @see EnableWebSecurity
 *
 * @author Rob Winch
 */
@Order(100)
public abstract class WebSecurityConfigurerAdapter implements
		WebSecurityConfigurer<WebSecurity> {
	private final Log logger = LogFactory.getLog(WebSecurityConfigurerAdapter.class);

	private ApplicationContext context;

	private ContentNegotiationStrategy contentNegotiationStrategy = new HeaderContentNegotiationStrategy();

	/**
	 * 在每个安全对象创建之后需要执行后置动作的 后置动作处理器，这里的缺省值
	 * 其实只是抛出异常声明IoC容器中必须存在一个ObjectPostProcessor bean：
	 * 参考 @EnableWebSecurity => @EnableGlobalAuthentication=> AuthenticationConfiguration => ObjectPostProcessorConfiguration
	 */
	private ObjectPostProcessor<Object> objectPostProcessor = new ObjectPostProcessor<Object>() {
		public <T> T postProcess(T object) {
			throw new IllegalStateException(
					ObjectPostProcessor.class.getName()
							+ " is a required bean. Ensure you have used @EnableWebSecurity and @Configuration");
		}
	};

	/**
	 * 配置 WebSecurity 需要使用到的认证配置，可以认为是全局认证配置，会通过 set 方法被自动注入,
	 * 该属性会用于从IoC容器获取目标 WebSecurity/HttpSecurity 所要直接使用的 AuthenticationManager 的双亲
	 * AuthenticationManager 。 该方式可能用得上，也可能用不上，要看开发人员是配置使用
	 * localConfigureAuthenticationBldr 还是使用该属性用于构建目标 WebSecurity/HttpSecurity 所要直接使用的
	 * AuthenticationManager 的双亲 AuthenticationManager。
	 */
	private AuthenticationConfiguration authenticationConfiguration;
	/**
	 * AuthenticationManager 构建器，缺省使用 : DefaultPasswordEncoderAuthenticationManagerBuilder
	 * 所有构建的 AuthenticationManager 会是目标 WebSecurity/HttpSecurity 所要直接使用的 AuthenticationManager
	 */
	private AuthenticationManagerBuilder authenticationBuilder;
	/**
	 * 通过setApplicationContext 方法进行初始化
	 * AuthenticationManager 构建器，缺省使用 : DefaultPasswordEncoderAuthenticationManagerBuilder
	 * 所要构建的 AuthenticationManagerBuilder 会是目标 WebSecurity/HttpSecurity 所要直接使用的
	 * AuthenticationManager 的双亲 AuthenticationManager。 不过缺省情况下，也就是开发人员不在子类
	 * 中覆盖实现 void configure(AuthenticationManagerBuilder auth) 的情况下, 该 localConfigureAuthenticationBldr
	 * 不会被用于构建目标 WebSecurity/HttpSecurity 所要直接使用的 AuthenticationManager 的双亲
	 * AuthenticationManager, 这种情况下的双亲 AuthenticationManager 会来自 authenticationConfiguration
	 */
	private AuthenticationManagerBuilder localConfigureAuthenticationBldr;
	/**
	 * 是否禁用 localConfigureAuthenticationBldr, 缺省情况下，也就是开发人员不在子类中覆盖实现
	 * void configure(AuthenticationManagerBuilder auth) 的情况下,  当前 WebSecurityConfigurerAdapter
	 * 缺省提供的 void configure(AuthenticationManagerBuilder auth)  方法实现会将该标志设置为 true,
	 * 也就是不使用 localConfigureAuthenticationBldr 构建目标 WebSecurity/HttpSecurity 所要直接使用的
	 * AuthenticationManager 的双亲 AuthenticationManager, 而是使用 authenticationConfiguration
	 * 提供的 AuthenticationManager 作为 双亲 AuthenticationManager
	 */
	private boolean disableLocalConfigureAuthenticationBldr;
	/**
	 * 标志属性 : 目标 WebSecurity/HttpSecurity 所要直接使用的AuthenticationManager的双亲 authenticationManager
	 * 是否已经初始化
	 */
	private boolean authenticationManagerInitialized;
	/**
	 * 目标 WebSecurity/HttpSecurity 所要直接使用的AuthenticationManager的双亲 authenticationManager
	 */
	private AuthenticationManager authenticationManager;
	/**
	 * 根据传入的 Authentication 的类型判断一个 Authentication 是否可被信任,
	 * 缺省使用实现机制 AuthenticationTrustResolverImpl 可被设置
	 */
	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
	/**
	 * HTTP 安全构建器，用于配置匹配特定URL模式的控制器方法的安全，构建产物是 DefaultSecurityFilterChain
	 */
	private HttpSecurity http;
	/**
	 * 是否禁用缺省配置,缺省为 false，可以通过当前类构造函数设置为true
	 */
	private boolean disableDefaults;

	/**
	 * 缺省构造函数， 缺省配置机制启用 : disableDefaults == false
	 * 
	 * Creates an instance with the default configuration enabled.
	 */
	protected WebSecurityConfigurerAdapter() {
		this(false);
	}

	/**
	 * Creates an instance which allows specifying if the default configuration should be
	 * enabled. Disabling the default configuration should be considered more advanced
	 * usage as it requires more understanding of how the framework is implemented.
	 *
	 * @param disableDefaults true if the default configuration should be disabled, else
	 * false
	 */
	protected WebSecurityConfigurerAdapter(boolean disableDefaults) {
		this.disableDefaults = disableDefaults;
	}

	/**
	 * 开发人员可以覆盖该方法用于配置指定的 AuthenticationManagerBuilder auth,
	 * 如果开发人员这么做了，那么这里所被配置的 auth , 其实就是当前配置器的属性
	 * localConfigureAuthenticationBldr 会被用于构建 WebSecurity/HttpSecurity
	 * 所要使用的 AuthenticationManager 的双亲 AuthenticationManager。
	 * 如果开发人员不覆盖实现此方法，此缺省实现其实只是设置一个禁用标志，禁用
	 * localConfigureAuthenticationBldr, 此时 WebSecurity/HttpSecurity 所要使
	 * 用的 AuthenticationManager 的双亲 AuthenticationManager 将会来自
	 * authenticationConfiguration.getAuthenticationManager()
	 *
	 * Used by the default implementation of {@link #authenticationManager()} to attempt
	 * to obtain an {@link AuthenticationManager}. If overridden, the
	 * {@link AuthenticationManagerBuilder} should be used to specify the
	 * {@link AuthenticationManager}.
	 *
	 * <p>
	 * The {@link #authenticationManagerBean()} method can be used to expose the resulting
	 * {@link AuthenticationManager} as a Bean. The {@link #userDetailsServiceBean()} can
	 * be used to expose the last populated {@link UserDetailsService} that is created
	 * with the {@link AuthenticationManagerBuilder} as a Bean. The
	 * {@link UserDetailsService} will also automatically be populated on
	 * {@link HttpSecurity#getSharedObject(Class)} for use with other
	 * {@link SecurityContextConfigurer} (i.e. RememberMeConfigurer )
	 * </p>
	 *
	 * <p>
	 * For example, the following configuration could be used to register in memory
	 * authentication that exposes an in memory {@link UserDetailsService}:
	 * </p>
	 *
	 * <pre>
	 * &#064;Override
	 * protected void configure(AuthenticationManagerBuilder auth) {
	 * 	auth
	 * 	// enable in memory based authentication with a user named
	 * 	// &quot;user&quot; and &quot;admin&quot;
	 * 	.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;).and()
	 * 			.withUser(&quot;admin&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;, &quot;ADMIN&quot;);
	 * }
	 *
	 * // Expose the UserDetailsService as a Bean
	 * &#064;Bean
	 * &#064;Override
	 * public UserDetailsService userDetailsServiceBean() throws Exception {
	 * 	return super.userDetailsServiceBean();
	 * }
	 *
	 * </pre>
	 *
	 * @param auth the {@link AuthenticationManagerBuilder} to use
	 * @throws Exception
	 */
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		this.disableLocalConfigureAuthenticationBldr = true;
	}

	/**
	 * 用于获取HttpSecurity实例
	 * 我们继承这个类, 重写 configure(http) 方法的时候, 会在 httpSecurity.configurers 里加入 filter
	 * http.csrf() 会将 CsrfConfigurer<HttpSecurity> 存入 HttpSecurity.configurers 中
	 * http.csrf().disable() 从 HttpSecurity.configurers 中移除 CsrfConfigurer
	 * 依次类推
	 *
	 * Creates the {@link HttpSecurity} or returns the current instance
	 *
	 * ] * @return the {@link HttpSecurity}
	 * @throws Exception
	 */
	@SuppressWarnings({ "rawtypes", "unchecked" })
	protected final HttpSecurity getHttp() throws Exception {
		if (http != null) {
			return http;
		}

		// 事件发布器
		DefaultAuthenticationEventPublisher eventPublisher = objectPostProcessor
				.postProcess(new DefaultAuthenticationEventPublisher());
		localConfigureAuthenticationBldr.authenticationEventPublisher(eventPublisher);

		/**
		 * 获取认证管理器
		 * 会调用 configure(AuthenticationManagerBuilder auth)
 		 */
		AuthenticationManager authenticationManager = authenticationManager();
		/**
		 * 设置在父级里面, 此变量也是在 setObjectPostProcessor() 方法里被赋值
		 * authenticationBuilder 所要构建的目标 AuthenticationManager 才是
		 * 当前配置器所配置的 WebSecurity/HttpSecurity 所要直接使用的  AuthenticationManager
		 */
		authenticationBuilder.parentAuthenticationManager(authenticationManager);
		authenticationBuilder.authenticationEventPublisher(eventPublisher);
		// 创建共享对象
		Map<Class<? extends Object>, Object> sharedObjects = createSharedObjects();

		// 创建了一个 http 实例
		http = new HttpSecurity(objectPostProcessor, authenticationBuilder,
				sharedObjects);
		// 这就是默认被配置的过滤器链, 配置的顺序在别的地方有排序
		if (!disableDefaults) {
			// @formatter:off
			/**
			 * HttpSecurity http 的缺省配置
			 * headers()等方法将configure apply()到了http的属性configurers中，这里默认会注入10个configurer
 			 */
			http
				.csrf().and() // 应用 CsrfConfigurer
				.addFilter(new WebAsyncManagerIntegrationFilter()) // 添加过滤器 WebAsyncManagerIntegrationFilter
				.exceptionHandling().and() // 应用 ExceptionHandlingConfigurer 添加过滤器 ExceptionTranslationFilter
				.headers().and() // 应用 HeadersConfigurer 添加过滤器 HeaderWriterFilter
				.sessionManagement().and() // 应用 SessionManagementConfigurer 添加过滤器 SessionManagementFilter
				.securityContext().and() // 应用 SecurityContextConfigurer 添加过滤器 SecurityContextPersistenceFilter
				.requestCache().and() // 应用 RequestCacheConfigurer 添加过滤器 RequestCacheAwareFilter
				.anonymous().and() // 应用 AnonymousConfigurer 添加过滤器 AnonymousAuthenticationFilter
				.servletApi().and() // 应用 ServletApiConfigurer 添加过滤器 SecurityContextHolderAwareRequestFilter
				.apply(new DefaultLoginPageConfigurer<>()).and() // 应用 DefaultLoginPageConfigurer,默认的登录页面在这里生成
				.logout(); // 应用 LogoutConfigurer 添加过滤器 LogoutFilter
			// @formatter:on
			ClassLoader classLoader = this.context.getClassLoader();
			/**
			 * SpringFactoriesLoader 这个类实现了检索 META-INF/spring.factories 文件，并获取指定接口的配置的功能。
			 * 这是 java spi 的约定, 基于这样一个约定就能很好的找到服务接口的实现类，而不需要再代码里制定
			 */
			List<AbstractHttpConfigurer> defaultHttpConfigurers =
					SpringFactoriesLoader.loadFactories(AbstractHttpConfigurer.class, classLoader);

			// 则加入 http 配置类里面
			for (AbstractHttpConfigurer configurer : defaultHttpConfigurers) {
				http.apply(configurer);
			}
		}
		// 调用被子类覆盖重写的方法, 这个方法也就是我们使用 spring security 的主要配置的方法
		configure(http);
		return http;
	}

	/**
	 * Override this method to expose the {@link AuthenticationManager} from
	 * {@link #configure(AuthenticationManagerBuilder)} to be exposed as a Bean. For
	 * example:
	 *
	 * <pre>
	 * &#064;Bean(name name="myAuthenticationManager")
	 * &#064;Override
	 * public AuthenticationManager authenticationManagerBean() throws Exception {
	 *     return super.authenticationManagerBean();
	 * }
	 * </pre>
	 *
	 * @return the {@link AuthenticationManager}
	 * @throws Exception
	 */
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return new AuthenticationManagerDelegator(authenticationBuilder, context);
	}

	/**
	 * 获取构建 WebSecurity/HttpSecurity所要使用的 AuthenticationManager 的
	 * 双亲 AuthenticationManager，这里的策略是 :
	 * 1. 如果开发人员覆盖实现了 #configure(AuthenticationManagerBuilder) ,
	 * 则会使用开发人员覆盖实现了的 AuthenticationManagerBuilder , 其实也就是
	 * 当前配置器的 localConfigureAuthenticationBldr 构建一个 AuthenticationManager
	 * 并返回和使用;
	 * 2. 如果开发人员没有覆盖实现 #configure(AuthenticationManagerBuilder) ,
	 * 则会使用  authenticationConfiguration#getAuthenticationManager() 提供的
	 * AuthenticationManager, 这是从IoC容器中根据类型查找得到的一个 AuthenticationManager
	 * 
	 * Gets the {@link AuthenticationManager} to use. The default strategy is if
	 * {@link #configure(AuthenticationManagerBuilder)} method is overridden to use the
	 * {@link AuthenticationManagerBuilder} that was passed in. Otherwise, autowire the
	 * {@link AuthenticationManager} by type.
	 *
	 * @return the {@link AuthenticationManager} to use
	 * @throws Exception
	 */
	protected AuthenticationManager authenticationManager() throws Exception {
		if (!authenticationManagerInitialized) {
			/**
			 * authenticationManager 尚未初始化的情况，在这里进行初始化
			 * 调用 configure(AuthenticationManagerBuilder auth) 用于配置  localConfigureAuthenticationBldr,
			 * 该方法有可能被开发人员覆盖实现（覆盖方法可以为接下来的AuthenticationManagerBuilder.build()方法提供SecurityConfigurer配置）
			 */
			configure(localConfigureAuthenticationBldr);
			if (disableLocalConfigureAuthenticationBldr) {
				/**
				 * 如果开发人员没有覆盖实现 configure(AuthenticationManagerBuilder auth)
				 * 方法， 则该方法的缺省实现会设置 disableLocalConfigureAuthenticationBldr=true,
				 * 这种情况下会使用 authenticationConfiguration 获取IoC容器中配置的 AuthenticationManager
				 * 作为目标WebSecurity/HttpSecurity 所要直接使用的 AuthenticationManager 的双亲
				 */
				authenticationManager = authenticationConfiguration
						.getAuthenticationManager();
			}
			else {
				/**
				 * 如果开发人员覆盖实现了 configure(AuthenticationManagerBuilder auth)
				 * 方法，则 localConfigureAuthenticationBldr 会被用于构建一个 AuthenticationManager,
				 * 该 AuthenticationManager 会充当目标WebSecurity/HttpSecurity 所要直接使用的
				 * AuthenticationManager 的双亲
				 *
				 * localConfigureAuthenticationBldr通过setApplicationContext(ApplicationContext context)初始化
				 */
				authenticationManager = localConfigureAuthenticationBldr.build();
			}
			// authenticationManager 初始化完成的情况，设置相应标志
			authenticationManagerInitialized = true;
		}
		return authenticationManager;
	}

	/**
	 * Override this method to expose a {@link UserDetailsService} created from
	 * {@link #configure(AuthenticationManagerBuilder)} as a bean. In general only the
	 * following override should be done of this method:
	 *
	 * <pre>
	 * &#064;Bean(name = &quot;myUserDetailsService&quot;)
	 * // any or no name specified is allowed
	 * &#064;Override
	 * public UserDetailsService userDetailsServiceBean() throws Exception {
	 * 	return super.userDetailsServiceBean();
	 * }
	 * </pre>
	 *
	 * To change the instance returned, developers should change
	 * {@link #userDetailsService()} instead
	 * @return the {@link UserDetailsService}
	 * @throws Exception
	 * @see #userDetailsService()
	 */
	public UserDetailsService userDetailsServiceBean() throws Exception {
		AuthenticationManagerBuilder globalAuthBuilder = context
				.getBean(AuthenticationManagerBuilder.class);
		return new UserDetailsServiceDelegator(Arrays.asList(
				localConfigureAuthenticationBldr, globalAuthBuilder));
	}

	/**
	 * Allows modifying and accessing the {@link UserDetailsService} from
	 * {@link #userDetailsServiceBean()} without interacting with the
	 * {@link ApplicationContext}. Developers should override this method when changing
	 * the instance of {@link #userDetailsServiceBean()}.
	 *
	 * @return the {@link UserDetailsService} to use
	 */
	protected UserDetailsService userDetailsService() {
		AuthenticationManagerBuilder globalAuthBuilder = context
				.getBean(AuthenticationManagerBuilder.class);
		return new UserDetailsServiceDelegator(Arrays.asList(
				localConfigureAuthenticationBldr, globalAuthBuilder));
	}

	@Override
	public void init(final WebSecurity web) throws Exception {
		// 初始化了一个 httpSecurity 对象
		final HttpSecurity http = getHttp();
		// 将 httpSecurity 设置进 webSecurity
		web.addSecurityFilterChainBuilder(http).postBuildAction(new Runnable() {
			public void run() {
				// 只设置了共享的变量 securityInterceptor
				FilterSecurityInterceptor securityInterceptor = http
						.getSharedObject(FilterSecurityInterceptor.class);
				// FilterSecurityInterceptor 加入 WebSecurity
				web.securityInterceptor(securityInterceptor);
			}
		});
	}

	/**
	 * 可以配置需要忽略的请求
	 * 
	 * Override this method to configure {@link WebSecurity}. For example, if you wish to
	 * ignore certain requests.
	 */
	@Override
	public void configure(WebSecurity web) throws Exception {
	}

	/**
	 * 覆盖实现此方法来自定义配置 HttpSecurity, 这里的实现是一个缺省实现
	 *
	 * Override this method to configure the {@link HttpSecurity}. Typically subclasses
	 * should not invoke this method by calling super as it may override their
	 * configuration. The default configuration is:
	 *
	 * <pre>
	 * http.authorizeRequests().anyRequest().authenticated().and().formLogin().and().httpBasic();
	 * </pre>
	 *
	 * @param http the {@link HttpSecurity} to modify
	 * @throws Exception if an error occurs
	 */
	// @formatter:off
	protected void configure(HttpSecurity http) throws Exception {
		logger.debug("Using default configure(HttpSecurity). If subclassed this will potentially override subclass configure(HttpSecurity).");

		http
			.authorizeRequests() // 应用 ExpressionUrlAuthorizationConfigurer 添加拦截器 FilterSecurityInterceptor
				.anyRequest() // 增加RequestMatcher为任何请求都可以访问
				.authenticated() // authenticated()必须登录后才能访问
				.and()
				/**
				 * 应用FormLoginConfigurer 添加过滤器 UsernamePasswordAuthenticationFilter
				 * .formLogin().loginPage("/login3") // 设置登录/登出url，跳转登录页面的控制器，该地址要保证和表单提交的地址一致
				 */
			.formLogin()
				.and()
			.httpBasic(); // 应用HttpBasicConfigurer 添加过滤器 BasicAuthenticationFilter
	}
	// @formatter:on

	/**
	 * Gets the ApplicationContext
	 * @return the context
	 */
	protected final ApplicationContext getApplicationContext() {
		return this.context;
	}

	@Autowired
	public void setApplicationContext(ApplicationContext context) {
		this.context = context;

		ObjectPostProcessor<Object> objectPostProcessor = context.getBean(ObjectPostProcessor.class);
		
		// 密码加密器，口令加密器，使用当前  WebSecurityConfigurerAdapter 的内部嵌套类 LazyPasswordEncoder
		LazyPasswordEncoder passwordEncoder = new LazyPasswordEncoder(context);

		// 目标 WebSecurity/HttpSecurity 所要直接使用的  AuthenticationManager 的构建器
		authenticationBuilder = new DefaultPasswordEncoderAuthenticationManagerBuilder(objectPostProcessor, passwordEncoder);
		/**
		 * 这里相当于localConfigureAuthenticationBldr 为 继承 DefaultPasswordEncoderAuthenticationManagerBuilder的子类
		 * 
		 * 目标 WebSecurity/HttpSecurity 所要直接使用的  AuthenticationManager  的双亲  AuthenticationManager
		 * 的构建器, 可能被用的上，也可能用不上，要看开发人员是否决定使用这个 localConfigureAuthenticationBldr
		 */
		localConfigureAuthenticationBldr = new DefaultPasswordEncoderAuthenticationManagerBuilder(objectPostProcessor, passwordEncoder) {
			@Override
			public AuthenticationManagerBuilder eraseCredentials(boolean eraseCredentials) {
				authenticationBuilder.eraseCredentials(eraseCredentials);
				return super.eraseCredentials(eraseCredentials);
			}

		};
	}

	/**
	 * 依赖注入 AuthenticationTrustResolver ， 如果容器中有 AuthenticationTrustResolver bean
	 * 则使用，否则则使用缺省值 : AuthenticationTrustResolverImpl
	 */
	@Autowired(required = false)
	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		this.trustResolver = trustResolver;
	}

	/**
	 * 依赖注入 ContentNegotiationStrategy ， 如果容器中有 ContentNegotiationStrategy bean
	 * 则使用，否则则使用缺省值 : HeaderContentNegotiationStrategy
	 */
	@Autowired(required = false)
	public void setContentNegotationStrategy(
			ContentNegotiationStrategy contentNegotiationStrategy) {
		this.contentNegotiationStrategy = contentNegotiationStrategy;
	}

	@Autowired
	public void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
		this.objectPostProcessor = objectPostProcessor;
	}

	@Autowired
	public void setAuthenticationConfiguration(
			AuthenticationConfiguration authenticationConfiguration) {
		this.authenticationConfiguration = authenticationConfiguration;
	}

	/**
	 * Creates the shared objects
	 *
	 * @return the shared Objects
	 */
	private Map<Class<? extends Object>, Object> createSharedObjects() {
		Map<Class<? extends Object>, Object> sharedObjects = new HashMap<Class<? extends Object>, Object>();
		sharedObjects.putAll(localConfigureAuthenticationBldr.getSharedObjects());
		sharedObjects.put(UserDetailsService.class, userDetailsService());
		// 将应用上下文也放入共享对象中
		sharedObjects.put(ApplicationContext.class, context);
		sharedObjects.put(ContentNegotiationStrategy.class, contentNegotiationStrategy);
		sharedObjects.put(AuthenticationTrustResolver.class, trustResolver);
		return sharedObjects;
	}

	/**
	 * Delays the use of the {@link UserDetailsService} from the
	 * {@link AuthenticationManagerBuilder} to ensure that it has been fully configured.
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	static final class UserDetailsServiceDelegator implements UserDetailsService {
		private List<AuthenticationManagerBuilder> delegateBuilders;
		private UserDetailsService delegate;
		private final Object delegateMonitor = new Object();

		UserDetailsServiceDelegator(List<AuthenticationManagerBuilder> delegateBuilders) {
			if (delegateBuilders.contains(null)) {
				throw new IllegalArgumentException(
						"delegateBuilders cannot contain null values. Got "
								+ delegateBuilders);
			}
			this.delegateBuilders = delegateBuilders;
		}

		public UserDetails loadUserByUsername(String username)
				throws UsernameNotFoundException {
			if (delegate != null) {
				return delegate.loadUserByUsername(username);
			}

			synchronized (delegateMonitor) {
				if (delegate == null) {
					for (AuthenticationManagerBuilder delegateBuilder : delegateBuilders) {
						delegate = delegateBuilder.getDefaultUserDetailsService();
						if (delegate != null) {
							break;
						}
					}

					if (delegate == null) {
						throw new IllegalStateException("UserDetailsService is required.");
					}
					this.delegateBuilders = null;
				}
			}

			return delegate.loadUserByUsername(username);
		}
	}

	/**
	 * 内部嵌套类，该类的目的是包装一个 AuthenticationManager ， 该被包装的
	 * AuthenticationManager 会由该 AuthenticationManagerDelegator 的构造函数
	 * 参数对象 delegateBuilder 在目标 AuthenticationManager 首次被使用时构建。
	 * 这么做的目的是确保 AuthenticationManager 被调用时，它已经被完全配置。
	 *
	 * Delays the use of the {@link AuthenticationManager} build from the
	 * {@link AuthenticationManagerBuilder} to ensure that it has been fully configured.
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	static final class AuthenticationManagerDelegator implements AuthenticationManager {
		private AuthenticationManagerBuilder delegateBuilder;
		private AuthenticationManager delegate;
		private final Object delegateMonitor = new Object();
		private Set<String> beanNames;

		AuthenticationManagerDelegator(AuthenticationManagerBuilder delegateBuilder,
				ApplicationContext context) {
			Assert.notNull(delegateBuilder, "delegateBuilder cannot be null");
			Field parentAuthMgrField = ReflectionUtils.findField(
					AuthenticationManagerBuilder.class, "parentAuthenticationManager");
			ReflectionUtils.makeAccessible(parentAuthMgrField);
			beanNames = getAuthenticationManagerBeanNames(context);
			validateBeanCycle(
					ReflectionUtils.getField(parentAuthMgrField, delegateBuilder),
					beanNames);
			this.delegateBuilder = delegateBuilder;
		}

		public Authentication authenticate(Authentication authentication)
				throws AuthenticationException {
			if (delegate != null) {
				// 如果被代理的 AuthenticationManager delegate 已经被构建则直接使用它进行认证
				return delegate.authenticate(authentication);
			}

			synchronized (delegateMonitor) {
				if (delegate == null) {
					/**
					 * 如果被代理的 AuthenticationManager delegate 尚未被构建，则在本次认证调用
					 * 中先对其进行构建，构建成功后忘掉所用的delegateBuilder
					 * 该模式中，这次认证也是对被代理的目标 AuthenticationManager 的首次认证调用
					 */
					delegate = this.delegateBuilder.getObject();
					this.delegateBuilder = null;
				}
			}

			// 对目标 AuthenticationManager 的首次认证调用
			return delegate.authenticate(authentication);
		}

		// 从指定应用上下文及其祖先上下文中查找类型为  AuthenticationManager 的 bean 的名称，可能有多个
		private static Set<String> getAuthenticationManagerBeanNames(
				ApplicationContext applicationContext) {
			String[] beanNamesForType = BeanFactoryUtils
					.beanNamesForTypeIncludingAncestors(applicationContext,
							AuthenticationManager.class);
			return new HashSet<>(Arrays.asList(beanNamesForType));
		}

		// 确保没有循环依赖
		private static void validateBeanCycle(Object auth, Set<String> beanNames) {
			if (auth != null && !beanNames.isEmpty()) {
				if (auth instanceof Advised) {
					Advised advised = (Advised) auth;
					TargetSource targetSource = advised.getTargetSource();
					if (targetSource instanceof LazyInitTargetSource) {
						LazyInitTargetSource lits = (LazyInitTargetSource) targetSource;
						if (beanNames.contains(lits.getTargetBeanName())) {
							throw new FatalBeanException(
									"A dependency cycle was detected when trying to resolve the AuthenticationManager. Please ensure you have configured authentication.");
						}
					}
				}
				beanNames = Collections.emptySet();
			}
		}
	}

	/**
	 * AuthenticationManagerBuilder默认实现
	 */
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

	// 内部嵌套类，延迟口令/密码加密器，将对口令/密码加密器对象的获取延迟到对其进行首次调用时
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
			PasswordEncoder passwordEncoder = getBeanOrNull(PasswordEncoder.class);
			if (passwordEncoder == null) {
				passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
			}
			this.passwordEncoder = passwordEncoder;
			return passwordEncoder;
		}

		private <T> T getBeanOrNull(Class<T> type) {
			try {
				return this.applicationContext.getBean(type);
			} catch(NoSuchBeanDefinitionException notFound) {
				return null;
			}
		}

		@Override
		public String toString() {
			return getPasswordEncoder().toString();
		}
	}
}
