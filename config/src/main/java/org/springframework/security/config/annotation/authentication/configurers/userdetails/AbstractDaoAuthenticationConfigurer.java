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
package org.springframework.security.config.annotation.authentication.configurers.userdetails;

import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;

/**
 * 除了来自基类和所实现接口定义的能力，AbstractDaoAuthenticationConfigurer自身又为一个安全配置器进行了如下定义:
 * 1.所要创建的AuthenticationProvider是一个DaoAuthenticationProvider;
 * 2.提供使用者设定目标DaoAuthenticationProvider属性userDetailsService/userDetailsPasswordService的功能;
 * 3.提供使用者设定目标DaoAuthenticationProvider属性passwordEncoder的功能;
 * 4.提供使用者设定配置过程中安全对象后置处理器的功能;
 *
 * Allows configuring a {@link DaoAuthenticationProvider}
 *
 * @author Rob Winch
 * @since 3.2
 *
 * @param <B> the type of the {@link SecurityBuilder}
 * @param <C> the type of {@link AbstractDaoAuthenticationConfigurer} this is
 * @param <U> The type of {@link UserDetailsService} that is being used
 *
 */
abstract class AbstractDaoAuthenticationConfigurer<B extends ProviderManagerBuilder<B>, C extends AbstractDaoAuthenticationConfigurer<B, C, U>, U extends UserDetailsService>
		extends UserDetailsAwareConfigurer<B, U> {

	/**
	 * 将要配置到目标安全构建器的 AuthenticationProvider， 默认是一个 DaoAuthenticationProvider
	 */
	private DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
	/**
	 * 将要设置到 provider 的 UserDetailsService ，可以是 UserDetailsService 的子类，将会由使用者提供
	 */
	private final U userDetailsService;

	/**
	 * 构造函数，使用指定的 UserDetailsService 或者 UserDetailsPasswordService
	 * 
	 * Creates a new instance
	 *
	 * @param userDetailsService
	 */
	protected AbstractDaoAuthenticationConfigurer(U userDetailsService) {
		// 记录使用者提供的 UserDetailsService
		this.userDetailsService = userDetailsService;
		// 设置 userDetailsService 到 provider
		provider.setUserDetailsService(userDetailsService);
		if (userDetailsService instanceof UserDetailsPasswordService) {
			this.provider.setUserDetailsPasswordService((UserDetailsPasswordService) userDetailsService);
		}
	}

	/**
	 * Adds an {@link ObjectPostProcessor} for this class.
	 *
	 * @param objectPostProcessor
	 * @return the {@link AbstractDaoAuthenticationConfigurer} for further customizations
	 */
	@SuppressWarnings("unchecked")
	public C withObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
		addObjectPostProcessor(objectPostProcessor);
		return (C) this;
	}

	/**
	 * 设置所要配置到安全构建器上的provider的密码加密器
	 * 
	 * Allows specifying the {@link PasswordEncoder} to use with the
	 * {@link DaoAuthenticationProvider}. The default is to use plain text.
	 *
	 * @param passwordEncoder The {@link PasswordEncoder} to use.
	 * @return the {@link AbstractDaoAuthenticationConfigurer} for further customizations
	 */
	@SuppressWarnings("unchecked")
	public C passwordEncoder(PasswordEncoder passwordEncoder) {
		// 往认证提供者设置PasswordEncoder(密码加密器)
		provider.setPasswordEncoder(passwordEncoder);
		return (C) this;
	}

	public C userDetailsPasswordManager(UserDetailsPasswordService passwordManager) {
		provider.setUserDetailsPasswordService(passwordManager);
		return (C) this;
	}

	/**
	 * SecurityConfigurer 接口定义的配置方法：对目标安全配置器builder进行配置
	 * 1. 对 provider 进行后置处理;
	 * 2. 将 provider 设置到 builder 上
	 */
	@Override
	public void configure(B builder) throws Exception {
		provider = postProcess(provider);
		builder.authenticationProvider(provider);
	}

	/**
	 * Gets the {@link UserDetailsService} that is used with the
	 * {@link DaoAuthenticationProvider}
	 *
	 * @return the {@link UserDetailsService} that is used with the
	 * {@link DaoAuthenticationProvider}
	 */
	@Override
	public U getUserDetailsService() {
		return userDetailsService;
	}
}
