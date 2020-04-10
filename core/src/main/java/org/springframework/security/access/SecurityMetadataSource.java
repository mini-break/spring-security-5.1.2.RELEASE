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

package org.springframework.security.access;

import java.util.Collection;

import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;

/**
 * 用于表示对受权限保护的"安全对象"的权限设置信息。一个该类对象可以被理解成一个映射表，映射表中的每一项包含如下信息
 * 1.安全对象
 * 2.安全对象所需权限信息
 * 
 * Implemented by classes that store and can identify the {@link ConfigAttribute}s that
 * applies to a given secure object invocation.
 *
 * @author Ben Alex
 */
public interface SecurityMetadataSource extends AopInfrastructureBean {
	// ~ Methods
	// ========================================================================================================

	/**
	 * 获取某个受保护的安全对象object的所需要的权限信息,是一组ConfigAttribute对象的集合，
	 * 如果该安全对象object不被当前SecurityMetadataSource对象支持,则抛出异常IllegalArgumentException。
	 * 该方法通常配合boolean supports(Class<?> clazz)一起使用，
	 * 先使用boolean supports(Class<?> clazz)确保安全对象能被当前SecurityMetadataSource支持，然后再调用该方法。
	 *
	 * Accesses the {@code ConfigAttribute}s that apply to a given secure object.
	 *
	 * @param object the object being secured
	 *
	 * @return the attributes that apply to the passed in secured object. Should return an
	 * empty collection if there are no applicable attributes.
	 *
	 * @throws IllegalArgumentException if the passed object is not of a type supported by
	 * the <code>SecurityMetadataSource</code> implementation
	 */
	Collection<ConfigAttribute> getAttributes(Object object)
			throws IllegalArgumentException;

	/**
	 * 获取该SecurityMetadataSource对象中保存的针对所有安全对象的权限信息的集合。
	 * 该方法的主要目的是被AbstractSecurityInterceptor用于启动时校验每个ConfigAttribute对象
	 *
	 * If available, returns all of the {@code ConfigAttribute}s defined by the
	 * implementing class.
	 * <p>
	 * This is used by the {@link AbstractSecurityInterceptor} to perform startup time
	 * validation of each {@code ConfigAttribute} configured against it.
	 *
	 * @return the {@code ConfigAttribute}s or {@code null} if unsupported
	 */
	Collection<ConfigAttribute> getAllConfigAttributes();

	/**
	 * 这里clazz表示安全对象的类型，该方法用于告知调用者当前SecurityMetadataSource是否支持此类安全对象，
	 * 只有支持的时候，才能对这类安全对象调用getAttributes方法
	 *
	 * Indicates whether the {@code SecurityMetadataSource} implementation is able to
	 * provide {@code ConfigAttribute}s for the indicated secure object type.
	 *
	 * @param clazz the class that is being queried
	 *
	 * @return true if the implementation can process the indicated class
	 */
	boolean supports(Class<?> clazz);
}
