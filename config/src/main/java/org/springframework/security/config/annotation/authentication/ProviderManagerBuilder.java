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
package org.springframework.security.config.annotation.authentication;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.SecurityBuilder;

/**
 * ProviderManagerBuilder扩展了SecurityBuilder接口增加了一个方法并且限制了build()方法只能创建AuthenticationManager类型的对象
 *
 * Interface for operating on a SecurityBuilder that creates a {@link ProviderManager}
 *
 * @author Rob Winch
 *
 * @param <B> the type of the {@link SecurityBuilder}
 */
public interface ProviderManagerBuilder<B extends ProviderManagerBuilder<B>> extends
		SecurityBuilder<AuthenticationManager> {

	/**
	 * 根据传入的自定义AuthenticationProvider添加身份验证。
	 * 由于AuthenticationProvider实现未知，因此必须在外部完成所有自定义，并立即返回ProviderManagerBuilder。
	 * 请注意，如果在添加AuthenticationProvider时发生错误，则抛出异常。
	 * 返回：ProviderManagerBuilder 允许向ProviderManagerBuilder提供进一步的身份验证
	 *
	 * Add authentication based upon the custom {@link AuthenticationProvider} that is
	 * passed in. Since the {@link AuthenticationProvider} implementation is unknown, all
	 * customizations must be done externally and the {@link ProviderManagerBuilder} is
	 * returned immediately.
	 *
	 * Note that an Exception is thrown if an error occurs when adding the {@link AuthenticationProvider}.
	 *
	 * @return a {@link ProviderManagerBuilder} to allow further authentication to be
	 * provided to the {@link ProviderManagerBuilder}
	 */
	B authenticationProvider(AuthenticationProvider authenticationProvider);
}
