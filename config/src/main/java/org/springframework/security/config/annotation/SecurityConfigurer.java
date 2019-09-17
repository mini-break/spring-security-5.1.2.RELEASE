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
package org.springframework.security.config.annotation;

/**
 * 该接口约定了Spring Security Config的各种安全配置器实现类的统一行为
 *
 * 初始化B, 且配置B的相关属性, 这句话能概括它的全部特性
 * B SecurityBuilder<O>的子类
 * O B.build()返回的object类型
 * 
 * Allows for configuring a {@link SecurityBuilder}. All {@link SecurityConfigurer} first
 * have their {@link #init(SecurityBuilder)} method invoked. After all
 * {@link #init(SecurityBuilder)} methods have been invoked, each
 * {@link #configure(SecurityBuilder)} method is invoked.
 *
 * @see AbstractConfiguredSecurityBuilder
 *
 * @author Rob Winch
 *
 * @param <O> The object being built by the {@link SecurityBuilder} B
 * @param <B> The {@link SecurityBuilder} that builds objects of type O. This is also the
 * {@link SecurityBuilder} that is being configured.
 */
public interface SecurityConfigurer<O, B extends SecurityBuilder<O>> {
	/**
	 * 初始化安全构建器
	 * 初始化 SecurityBuilder<O> 只创建设置了共享的变量，不会设置 configure() 中需要的特殊属性
	 *
	 * Initialize the {@link SecurityBuilder}. Here only shared state should be created
	 * and modified, but not properties on the {@link SecurityBuilder} used for building
	 * the object. This ensures that the {@link #configure(SecurityBuilder)} method uses
	 * the correct shared objects when building.
	 *
	 * @param builder
	 * @throws Exception
	 */
	void init(B builder) throws Exception;

	/**
	 * 配置安全构建器
	 * 设置SecurityBuilder<O>的特殊属性
	 * 
	 * Configure the {@link SecurityBuilder} by setting the necessary properties on the
	 * {@link SecurityBuilder}.
	 *
	 * @param builder
	 * @throws Exception
	 */
	void configure(B builder) throws Exception;
}
