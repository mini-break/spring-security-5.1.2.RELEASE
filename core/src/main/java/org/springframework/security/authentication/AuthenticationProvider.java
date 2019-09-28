/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * Spring Security中AuthenticationProvider接口抽象建模了认证提供者这一概念，某个认证提供者能认证符合某种特征的认证令牌Authentication
 * 
 * Indicates a class can process a specific
 * {@link org.springframework.security.core.Authentication} implementation.
 *
 * @author Ben Alex
 */
public interface AuthenticationProvider {
	// ~ Methods
	// ========================================================================================================

	/**
	 * 对提供的认证令牌对象 authentication 执行认证逻辑。如果认证成功，返回信息填充完整的
	 * 的认证令牌对象 authentication。 无法完成认证的话返回 null。此时调用者，通常是 ProviderManager
	 * 使用其他的认证提供者继续尝试认证该认证令牌对象
	 *
	 * Performs authentication with the same contract as
	 * {@link org.springframework.security.authentication.AuthenticationManager#authenticate(Authentication)}
	 * .
	 *
	 * @param authentication the authentication request object.
	 *
	 * @return a fully authenticated object including credentials. May return
	 * <code>null</code> if the <code>AuthenticationProvider</code> is unable to support
	 * authentication of the passed <code>Authentication</code> object. In such a case,
	 * the next <code>AuthenticationProvider</code> that supports the presented
	 * <code>Authentication</code> class will be tried.
	 *
	 * @throws AuthenticationException if authentication fails.
	 */
	Authentication authenticate(Authentication authentication)
			throws AuthenticationException;

	/**
	 * 返回 true 表示当前 AuthenticationProvider 能够支持对该 Authentication 对象的
	 * 认证。 不过返回 true 并不表示当前 AuthenticationProvider 能成功认证该 Authentication对象。
	 *
	 * 该方法通常被 ProviderManager 用作判断当前 AuthenticationProvider是否可以用于对某个 Authentication 执行认证的逻辑
	 *
	 * Returns <code>true</code> if this <Code>AuthenticationProvider</code> supports the
	 * indicated <Code>Authentication</code> object.
	 * <p>
	 * Returning <code>true</code> does not guarantee an
	 * <code>AuthenticationProvider</code> will be able to authenticate the presented
	 * instance of the <code>Authentication</code> class. It simply indicates it can
	 * support closer evaluation of it. An <code>AuthenticationProvider</code> can still
	 * return <code>null</code> from the {@link #authenticate(Authentication)} method to
	 * indicate another <code>AuthenticationProvider</code> should be tried.
	 * </p>
	 * <p>
	 * Selection of an <code>AuthenticationProvider</code> capable of performing
	 * authentication is conducted at runtime the <code>ProviderManager</code>.
	 * </p>
	 *
	 * @param authentication
	 *
	 * @return <code>true</code> if the implementation can more closely evaluate the
	 * <code>Authentication</code> class presented
	 */
	boolean supports(Class<?> authentication);
}
