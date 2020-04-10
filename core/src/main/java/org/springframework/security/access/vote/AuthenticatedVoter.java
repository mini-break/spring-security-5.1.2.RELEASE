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

package org.springframework.security.access.vote;

import java.util.Collection;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * 1.AuthenticatedVoter也是Spring Security内置的一个AccessDecisionVoter实现。
 *   其主要用来区分匿名用户、通过Remember-Me认证的用户和完全认证的用户。完全认证的用户是指由系统提供的登录入口进行成功登录认证的用户。
 * 2.AuthenticatedVoter可以处理的ConfigAttribute有IS_AUTHENTICATED_FULLY、IS_AUTHENTICATED_REMEMBERED和IS_AUTHENTICATED_ANONYMOUSLY。
 *   如果ConfigAttribute不在这三者范围之内，则AuthenticatedVoter将弃权。否则将视ConfigAttribute而定，
 *   如果ConfigAttribute为IS_AUTHENTICATED_ANONYMOUSLY，则不管用户是匿名的还是已经认证的都将投赞成票；
 *   如果是IS_AUTHENTICATED_REMEMBERED则仅当用户是由Remember-Me自动登录，或者是通过登录入口进行登录认证时才会投赞成票，否则将投反对票；
 *   而当ConfigAttribute为IS_AUTHENTICATED_FULLY时仅当用户是通过登录入口进行登录的才会投赞成票，否则将投反对票。
 * 3.AuthenticatedVoter是通过AuthenticationTrustResolver的isAnonymous()方法和isRememberMe()方法来判断
 *   SecurityContextHolder持有的Authentication是否为AnonymousAuthenticationToken或RememberMeAuthenticationToken的，
 *   即是否为IS_AUTHENTICATED_ANONYMOUSLY和IS_AUTHENTICATED_REMEMBERED。
 *
 * Votes if a {@link ConfigAttribute#getAttribute()} of
 * <code>IS_AUTHENTICATED_FULLY</code> or <code>IS_AUTHENTICATED_REMEMBERED</code> or
 * <code>IS_AUTHENTICATED_ANONYMOUSLY</code> is present. This list is in order of most
 * strict checking to least strict checking.
 * <p>
 * The current <code>Authentication</code> will be inspected to determine if the principal
 * has a particular level of authentication. The "FULLY" authenticated option means the
 * user is authenticated fully (i.e.
 * {@link org.springframework.security.authentication.AuthenticationTrustResolver#isAnonymous(Authentication)}
 * is false and
 * {@link org.springframework.security.authentication.AuthenticationTrustResolver#isRememberMe(Authentication)}
 * is false). The "REMEMBERED" will grant access if the principal was either authenticated
 * via remember-me OR is fully authenticated. The "ANONYMOUSLY" will grant access if the
 * principal was authenticated via remember-me, OR anonymously, OR via full
 * authentication.
 * <p>
 * All comparisons and prefixes are case sensitive.
 *
 * @author Ben Alex
 */
public class AuthenticatedVoter implements AccessDecisionVoter<Object> {
	// ~ Static fields/initializers
	// =====================================================================================

	/**
	 * 完全认证的用户
	 */
	public static final String IS_AUTHENTICATED_FULLY = "IS_AUTHENTICATED_FULLY";
	/**
	 * 通过记住我登录的用户
	 */
	public static final String IS_AUTHENTICATED_REMEMBERED = "IS_AUTHENTICATED_REMEMBERED";
	/**
	 * 匿名登录用户
	 */
	public static final String IS_AUTHENTICATED_ANONYMOUSLY = "IS_AUTHENTICATED_ANONYMOUSLY";
	// ~ Instance fields
	// ================================================================================================

	private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();

	// ~ Methods
	// ========================================================================================================

	/**
	 * 是否完全认证
	 */
	private boolean isFullyAuthenticated(Authentication authentication) {
		return (!authenticationTrustResolver.isAnonymous(authentication) && !authenticationTrustResolver
				.isRememberMe(authentication));
	}

	public void setAuthenticationTrustResolver(
			AuthenticationTrustResolver authenticationTrustResolver) {
		Assert.notNull(authenticationTrustResolver,
				"AuthenticationTrustResolver cannot be set to null");
		this.authenticationTrustResolver = authenticationTrustResolver;
	}

	@Override
	public boolean supports(ConfigAttribute attribute) {
		if ((attribute.getAttribute() != null)
				&& (IS_AUTHENTICATED_FULLY.equals(attribute.getAttribute())
						|| IS_AUTHENTICATED_REMEMBERED.equals(attribute.getAttribute()) || IS_AUTHENTICATED_ANONYMOUSLY
							.equals(attribute.getAttribute()))) {
			return true;
		}
		else {
			return false;
		}
	}

	/**
	 * This implementation supports any type of class, because it does not query the
	 * presented secure object.
	 *
	 * @param clazz the secure object type
	 *
	 * @return always {@code true}
	 */
	@Override
	public boolean supports(Class<?> clazz) {
		return true;
	}

	@Override
	public int vote(Authentication authentication, Object object,
			Collection<ConfigAttribute> attributes) {
		int result = ACCESS_ABSTAIN;

		for (ConfigAttribute attribute : attributes) {
			if (this.supports(attribute)) {
				result = ACCESS_DENIED;

				// 资源配置为需要登录访问
				if (IS_AUTHENTICATED_FULLY.equals(attribute.getAttribute())) {
					// 如果为完全认证，则通过
					if (isFullyAuthenticated(authentication)) {
						return ACCESS_GRANTED;
					}
				}

				// 资源配置为记住我
				if (IS_AUTHENTICATED_REMEMBERED.equals(attribute.getAttribute())) {
					if (authenticationTrustResolver.isRememberMe(authentication)
							|| isFullyAuthenticated(authentication)) {
						return ACCESS_GRANTED;
					}
				}

				// 资源配置为匿名访问
				if (IS_AUTHENTICATED_ANONYMOUSLY.equals(attribute.getAttribute())) {
					if (authenticationTrustResolver.isAnonymous(authentication)
							|| isFullyAuthenticated(authentication)
							|| authenticationTrustResolver.isRememberMe(authentication)) {
						return ACCESS_GRANTED;
					}
				}
			}
		}

		return result;
	}
}
