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
package org.springframework.security.config.annotation.authentication.configurers.provisioning;

import java.util.ArrayList;

import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * InMemoryUserDetailsManagerConfigurer是Spring Security Config提供的一个安全配置器SecurityConfigurer,
 * 用来配置一个安全构建器ProviderManagerBuilder(通常可以认为就是AuthenticationManagerBuilder),
 * 它为目标安全构建器提供的是一个基于内存存储用户账号详情的用户账号详情管理对象DaoAuthenticationProvider
 *
 * Configures an
 * {@link org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder}
 * to have in memory authentication. It also allows easily adding users to the in memory
 * authentication.
 *
 * @param <B> the type of the {@link ProviderManagerBuilder} that is being configured
 *
 * @author Rob Winch
 * @since 3.2
 */
public class InMemoryUserDetailsManagerConfigurer<B extends ProviderManagerBuilder<B>>
		extends UserDetailsManagerConfigurer<B, InMemoryUserDetailsManagerConfigurer<B>> {

	/**
	 * Creates a new instance
	 */
	public InMemoryUserDetailsManagerConfigurer() {
		// 设置UserDetailsService
		super(new InMemoryUserDetailsManager(new ArrayList<>()));
	}
}
