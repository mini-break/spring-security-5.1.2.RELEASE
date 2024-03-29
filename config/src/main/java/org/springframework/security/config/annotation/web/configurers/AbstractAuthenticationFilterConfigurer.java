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
package org.springframework.security.config.annotation.web.configurers;

import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.openid.OpenIDLoginConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Collections;

/**
 * Base class for configuring {@link AbstractAuthenticationFilterConfigurer}. This is
 * intended for internal use only.
 *
 * @see FormLoginConfigurer
 * @see OpenIDLoginConfigurer
 *
 * @param T refers to "this" for returning the current configurer
 * @param F refers to the {@link AbstractAuthenticationProcessingFilter} that is being
 * built
 *
 * @author Rob Winch
 * @since 3.2
 */
public abstract class AbstractAuthenticationFilterConfigurer<B extends HttpSecurityBuilder<B>, T extends AbstractAuthenticationFilterConfigurer<B, T, F>, F extends AbstractAuthenticationProcessingFilter>
		extends AbstractHttpConfigurer<T, B> {

	/**
	 * 认证过滤器  如：UsernamePasswordAuthenticationFilter
	 */
	private F authFilter;

	/**
	 * 对登录信息的扩展
	 */
	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

	private SavedRequestAwareAuthenticationSuccessHandler defaultSuccessHandler = new SavedRequestAwareAuthenticationSuccessHandler();
	/**
	 * 认证成功处理器
	 */
	private AuthenticationSuccessHandler successHandler = this.defaultSuccessHandler;

	/**
	 * 认证入口点
	 */
	private LoginUrlAuthenticationEntryPoint authenticationEntryPoint;

	/**
	 * 是否用户自定义登录页面
	 */
	private boolean customLoginPage;
	/**
	 * 登录页面url
	 */
	private String loginPage;
	/**
	 * 登录处理url
	 */
	private String loginProcessingUrl;

	/**
	 * 认证失败处理器
	 */
	private AuthenticationFailureHandler failureHandler;

	private boolean permitAll;

	private String failureUrl;

	/**
	 * Creates a new instance with minimal defaults
	 */
	protected AbstractAuthenticationFilterConfigurer() {
		// 设置默认登录页面
		setLoginPage("/login");
	}

	/**
	 * Creates a new instance
	 * @param authenticationFilter the {@link AbstractAuthenticationProcessingFilter} to
	 * use
	 * @param defaultLoginProcessingUrl the default URL to use for
	 * {@link #loginProcessingUrl(String)}
	 */
	protected AbstractAuthenticationFilterConfigurer(F authenticationFilter,
			String defaultLoginProcessingUrl) {
		this();
		this.authFilter = authenticationFilter;
		if (defaultLoginProcessingUrl != null) {
			loginProcessingUrl(defaultLoginProcessingUrl);
		}
	}

	/**
	 * Specifies where users will go after authenticating successfully if they have not
	 * visited a secured page prior to authenticating. This is a shortcut for calling
	 * {@link #defaultSuccessUrl(String)}.
	 *
	 * @param defaultSuccessUrl the default success url
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public final T defaultSuccessUrl(String defaultSuccessUrl) {
		return defaultSuccessUrl(defaultSuccessUrl, false);
	}

	/**
	 * alwaysUse: false 存在重定向功能
	 * 1.未登录情况下
	 * 浏览器输入http://ip:port/abc ----> 登录页面---->输入用户名/密码登录成功后----> http://ip:port/abc
	 * 2.登录情况下
	 * 浏览器输入http://ip:port/abc ----> http://ip:port/abc
	 *
	 * alwaysUse: true
	 * 假设defaultSuccessUrl: http://ip:port/aaa
	 * 浏览器输入http://ip:port/abc ----> 登录页面---->输入用户名/密码登录成功后----> http://ip:port/aaa
	 *
	 * Specifies where users will go after authenticating successfully if they have not
	 * visited a secured page prior to authenticating or {@code alwaysUse} is true. This
	 * is a shortcut for calling {@link #successHandler(AuthenticationSuccessHandler)}.
	 *
	 * @param defaultSuccessUrl the default success url
	 * @param alwaysUse true if the {@code defaultSuccessUrl} should be used after
	 * authentication despite if a protected page had been previously visited
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public final T defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
		SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
		handler.setDefaultTargetUrl(defaultSuccessUrl);
		handler.setAlwaysUseDefaultTargetUrl(alwaysUse);
		this.defaultSuccessHandler = handler;
		return successHandler(handler);
	}

	/**
	 * 配置自定义登录处理url
	 * Specifies the URL to validate the credentials.
	 *
	 * @param loginProcessingUrl the URL to validate username and password
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public T loginProcessingUrl(String loginProcessingUrl) {
		this.loginProcessingUrl = loginProcessingUrl;
		authFilter
				.setRequiresAuthenticationRequestMatcher(createLoginProcessingUrlMatcher(loginProcessingUrl));
		return getSelf();
	}

	/**
	 * Create the {@link RequestMatcher} given a loginProcessingUrl
	 * @param loginProcessingUrl creates the {@link RequestMatcher} based upon the
	 * loginProcessingUrl
	 * @return the {@link RequestMatcher} to use based upon the loginProcessingUrl
	 */
	protected abstract RequestMatcher createLoginProcessingUrlMatcher(
			String loginProcessingUrl);

	/**
	 * 配置用户自定义 AuthenticationDetailsSource
	 * Specifies a custom {@link AuthenticationDetailsSource}. The default is
	 * {@link WebAuthenticationDetailsSource}.
	 *
	 * @param authenticationDetailsSource the custom {@link AuthenticationDetailsSource}
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public final T authenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		this.authenticationDetailsSource = authenticationDetailsSource;
		return getSelf();
	}

	/**
	 * Specifies the {@link AuthenticationSuccessHandler} to be used. The default is
	 * {@link SavedRequestAwareAuthenticationSuccessHandler} with no additional properites
	 * set.
	 *
	 * @param successHandler the {@link AuthenticationSuccessHandler}.
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public final T successHandler(AuthenticationSuccessHandler successHandler) {
		// 设置登录成功处理器
		this.successHandler = successHandler;
		return getSelf();
	}

	/**
	 * Equivalent of invoking permitAll(true)
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public final T permitAll() {
		return permitAll(true);
	}

	/**
	 * Ensures the urls for {@link #failureUrl(String)} as well as for the {@link HttpSecurityBuilder}, the
	 * {@link #getLoginPage} and {@link #getLoginProcessingUrl} are granted access to any user.
	 *
	 * @param permitAll true to grant access to the URLs false to skip this step
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public final T permitAll(boolean permitAll) {
		this.permitAll = permitAll;
		return getSelf();
	}

	/**
	 * The URL to send users if authentication fails. This is a shortcut for invoking
	 * {@link #failureHandler(AuthenticationFailureHandler)}. The default is
	 * "/login?error".
	 *
	 * @param authenticationFailureUrl the URL to send users if authentication fails (i.e.
	 * "/login?error").
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public final T failureUrl(String authenticationFailureUrl) {
		T result = failureHandler(new SimpleUrlAuthenticationFailureHandler(
				authenticationFailureUrl));
		this.failureUrl = authenticationFailureUrl;
		return result;
	}

	/**
	 * Specifies the {@link AuthenticationFailureHandler} to use when authentication
	 * fails. The default is redirecting to "/login?error" using
	 * {@link SimpleUrlAuthenticationFailureHandler}
	 *
	 * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} to use
	 * when authentication fails.
	 * @return the {@link FormLoginConfigurer} for additional customization
	 */
	public final T failureHandler(
			AuthenticationFailureHandler authenticationFailureHandler) {
		this.failureUrl = null;
		this.failureHandler = authenticationFailureHandler;
		return getSelf();
	}

	@Override
	public void init(B http) throws Exception {
		// 修改登录认证默认路径(登录处理地址，失败跳转地址，注销成功跳转地址)
		updateAuthenticationDefaults();
		// 修改默认访问权限，对 loginPage、loginProcessingUrl、failureUrl 进行 permitAll 设置（如果用户配置了 permitAll 的话）
		updateAccessDefaults(http);
		// 注册认证入口点 （注册异常的处理器）
		registerDefaultAuthenticationEntryPoint(http);
	}

	@SuppressWarnings("unchecked")
	protected final void registerDefaultAuthenticationEntryPoint(B http) {
		registerAuthenticationEntryPoint(http, this.authenticationEntryPoint);
	}

	@SuppressWarnings("unchecked")
	protected final void registerAuthenticationEntryPoint(B http, AuthenticationEntryPoint authenticationEntryPoint) {
		ExceptionHandlingConfigurer<B> exceptionHandling = http
				.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionHandling == null) {
			return;
		}
		/**
		 * 向ExceptionHandlingConfigurer中加入认证入口点及匹配器
		 * authenticationEntryPoint通过初始化函数生成
		 */
		exceptionHandling.defaultAuthenticationEntryPointFor(
				postProcess(authenticationEntryPoint), getAuthenticationEntryPointMatcher(http));
	}

	protected final RequestMatcher getAuthenticationEntryPointMatcher(B http) {
		ContentNegotiationStrategy contentNegotiationStrategy = http
				.getSharedObject(ContentNegotiationStrategy.class);
		if (contentNegotiationStrategy == null) {
			contentNegotiationStrategy = new HeaderContentNegotiationStrategy();
		}

		MediaTypeRequestMatcher mediaMatcher = new MediaTypeRequestMatcher(
				contentNegotiationStrategy, MediaType.APPLICATION_XHTML_XML,
				new MediaType("image", "*"), MediaType.TEXT_HTML, MediaType.TEXT_PLAIN);
		mediaMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

		// Ajax请求匹配器
		RequestMatcher notXRequestedWith = new NegatedRequestMatcher(
				new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest"));

		return new AndRequestMatcher(Arrays.asList(notXRequestedWith, mediaMatcher));
	}

	@Override
	public void configure(B http) throws Exception {
		PortMapper portMapper = http.getSharedObject(PortMapper.class);
		if (portMapper != null) {
			authenticationEntryPoint.setPortMapper(portMapper);
		}

		RequestCache requestCache = http.getSharedObject(RequestCache.class);
		if (requestCache != null) {
			this.defaultSuccessHandler.setRequestCache(requestCache);
		}

		// 认证管理器设置
		authFilter.setAuthenticationManager(http
				.getSharedObject(AuthenticationManager.class));
		// 认证成功处理器
		authFilter.setAuthenticationSuccessHandler(successHandler);
		// 认证失败处理器
		authFilter.setAuthenticationFailureHandler(failureHandler);
		if (authenticationDetailsSource != null) {
			authFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
		}
		// 加入Session认证策略
		SessionAuthenticationStrategy sessionAuthenticationStrategy = http
				.getSharedObject(SessionAuthenticationStrategy.class);
		if (sessionAuthenticationStrategy != null) {
			authFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
		}
		RememberMeServices rememberMeServices = http
				.getSharedObject(RememberMeServices.class);
		if (rememberMeServices != null) {
			authFilter.setRememberMeServices(rememberMeServices);
		}
		F filter = postProcess(authFilter);
		// 将filter加入httpSecurity中(例如：UsernamePasswordAuthenticationFilter)
		http.addFilter(filter);
	}

	/**
	 * <p>
	 * Specifies the URL to send users to if login is required. If used with
	 * {@link WebSecurityConfigurerAdapter} a default login page will be generated when
	 * this attribute is not specified.
	 * </p>
	 *
	 * <p>
	 * If a URL is specified or this is not being used in conjuction with
	 * {@link WebSecurityConfigurerAdapter}, users are required to process the specified
	 * URL to generate a login page.
	 * </p>
	 */
	protected T loginPage(String loginPage) {
		setLoginPage(loginPage);
		// 修改认证默认配置,包括登录url,登出成功跳转url
		updateAuthenticationDefaults();
		// 用户自定义登录页面标识为true
		this.customLoginPage = true;
		return getSelf();
	}

	/**
	 *
	 * @return true if a custom login page has been specified, else false
	 */
	public final boolean isCustomLoginPage() {
		return customLoginPage;
	}

	/**
	 * 获取认证过滤器
	 * Gets the Authentication Filter
	 *
	 * @return the Authentication Filter
	 */
	protected final F getAuthenticationFilter() {
		return authFilter;
	}

	/**
	 * Sets the Authentication Filter
	 *
	 * @param authFilter the Authentication Filter
	 */
	protected final void setAuthenticationFilter(F authFilter) {
		this.authFilter = authFilter;
	}

	/**
	 * Gets the login page
	 *
	 * @return the login page
	 */
	protected final String getLoginPage() {
		return loginPage;
	}

	/**
	 * Gets the Authentication Entry Point
	 *
	 * @return the Authentication Entry Point
	 */
	protected final AuthenticationEntryPoint getAuthenticationEntryPoint() {
		return authenticationEntryPoint;
	}

	/**
	 * Gets the URL to submit an authentication request to (i.e. where username/password
	 * must be submitted)
	 *
	 * @return the URL to submit an authentication request to
	 */
	protected final String getLoginProcessingUrl() {
		return loginProcessingUrl;
	}

	/**
	 * Gets the URL to send users to if authentication fails
	 *
	 * @return the URL to send users if authentication fails (e.g. "/login?error").
	 */
	protected final String getFailureUrl() {
		return failureUrl;
	}

	/**
	 * 修改认证默认配置,包括登录url,登出成功跳转url
	 * 自定义登录页面时被两个方法调用：
	 * 1.loginPage(String loginPage)
	 * 2.init(B http)
	 * 
	 * Updates the default values for authentication.
	 *
	 * @throws Exception
	 */
	protected final void updateAuthenticationDefaults() {
		// 如果登录处理url未配置，则使用登录url作为登录处理url
		if (loginProcessingUrl == null) {
			loginProcessingUrl(loginPage);
		}
		if (failureHandler == null) {
			failureUrl(loginPage + "?error");
		}

		final LogoutConfigurer<B> logoutConfigurer = getBuilder().getConfigurer(
				LogoutConfigurer.class);
		if (logoutConfigurer != null && !logoutConfigurer.isCustomLogoutSuccess()) {
			// 自定义退出成功时跳转的页面
			logoutConfigurer.logoutSuccessUrl(loginPage + "?logout");
		}
	}

	/**
	 * Updates the default values for access.
	 */
	protected final void updateAccessDefaults(B http) {
		if (permitAll) {
			PermitAllSupport.permitAll(http, loginPage, loginProcessingUrl, failureUrl);
		}
	}

	/**
	 * 设置登录页面和登录认证入口
	 * Sets the loginPage and updates the {@link AuthenticationEntryPoint}.
	 * @param loginPage
	 */
	private void setLoginPage(String loginPage) {
		this.loginPage = loginPage;
		// 初始化LoginUrlAuthenticationEntryPoint
		this.authenticationEntryPoint = new LoginUrlAuthenticationEntryPoint(loginPage);
	}

	@SuppressWarnings("unchecked")
	private T getSelf() {
		return (T) this;
	}
}
