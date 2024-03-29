/*
 * Copyright 2002-2015 the original author or authors.
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

import org.springframework.context.ApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;

/**
 * 默认配置UserDetailsService
 * Lazily initializes the global authentication with a {@link UserDetailsService} if it is
 * not yet configured and there is only a single Bean of that type. Optionally, if a
 * {@link PasswordEncoder} is defined will wire this up too.
 *
 * @author Rob Winch
 * @since 4.1
 */
@Order(InitializeUserDetailsBeanManagerConfigurer.DEFAULT_ORDER)
class InitializeUserDetailsBeanManagerConfigurer
		extends GlobalAuthenticationConfigurerAdapter {

	static final int DEFAULT_ORDER = Ordered.LOWEST_PRECEDENCE - 5000;

	private final ApplicationContext context;

	/**
	 * @param context
	 */
	public InitializeUserDetailsBeanManagerConfigurer(ApplicationContext context) {
		this.context = context;
	}

	@Override
	public void init(AuthenticationManagerBuilder auth) throws Exception {
		// AbstractConfiguredSecurityBuilder中加入UserDetailsService配置
		auth.apply(new InitializeUserDetailsManagerConfigurer());
	}

	class InitializeUserDetailsManagerConfigurer
			extends GlobalAuthenticationConfigurerAdapter {
		@Override
		public void configure(AuthenticationManagerBuilder auth) throws Exception {
			if (auth.isConfigured()) {
				return;
			}
			/**
			 * 容器中获取用户详情服务bean（UserDetailsService 实例）
			 * InMemoryUserDetailsManager 来自 UserDetailsServiceAutoConfiguration
			 */
			UserDetailsService userDetailsService = getBeanOrNull(
					UserDetailsService.class);
			if (userDetailsService == null) {
				return;
			}

			PasswordEncoder passwordEncoder = getBeanOrNull(PasswordEncoder.class);
			/**
			 * 容器中获取用户详情密码修改服务bean
			 * InMemoryUserDetailsManager 来自 UserDetailsServiceAutoConfiguration
			 */
			UserDetailsPasswordService passwordManager = getBeanOrNull(UserDetailsPasswordService.class);

			DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
			provider.setUserDetailsService(userDetailsService);
			if (passwordEncoder != null) {
				provider.setPasswordEncoder(passwordEncoder);
			}
			if (passwordManager != null) {
				provider.setUserDetailsPasswordService(passwordManager);
			}
			provider.afterPropertiesSet();

			auth.authenticationProvider(provider);
		}

		/**
		 * 从容器中获取实例对象
		 */
		private <T> T getBeanOrNull(Class<T> type) {
			// 容器中获取指定类型的bean name
			String[] userDetailsBeanNames = InitializeUserDetailsBeanManagerConfigurer.this.context
					.getBeanNamesForType(type);
			if (userDetailsBeanNames.length != 1) {
				return null;
			}

			return InitializeUserDetailsBeanManagerConfigurer.this.context
					.getBean(userDetailsBeanNames[0], type);
		}
	}
}
