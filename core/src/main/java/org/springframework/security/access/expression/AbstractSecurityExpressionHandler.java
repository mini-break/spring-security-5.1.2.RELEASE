/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.access.expression;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.expression.BeanFactoryResolver;
import org.springframework.expression.BeanResolver;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * Spring Security安全表达式求值实现的通用逻辑基类，同具体某种底层安全表达式实现,比如Web安全,隔离开来。
 * 
 * Base implementation of the facade which isolates Spring Security's requirements for
 * evaluating security expressions from the implementation of the underlying expression
 * objects.
 *
 * @author Luke Taylor
 * @since 3.1
 */
public abstract class AbstractSecurityExpressionHandler<T> implements
		SecurityExpressionHandler<T>, ApplicationContextAware {
	/**
	 * 缺省使用 SpelExpressionParser
	 * 接口ExpressionParser用来解析一个字符串表达式
	 */
	private ExpressionParser expressionParser = new SpelExpressionParser();
	private BeanResolver br;
	private RoleHierarchy roleHierarchy;
	/**
	 * 缺省使用 denyAll 评估器
	 */
	private PermissionEvaluator permissionEvaluator = new DenyAllPermissionEvaluator();

	@Override
	public final ExpressionParser getExpressionParser() {
		return expressionParser;
	}

	public final void setExpressionParser(ExpressionParser expressionParser) {
		Assert.notNull(expressionParser, "expressionParser cannot be null");
		this.expressionParser = expressionParser;
	}

	/**
	 * 创建基于SecurityExpressionOperations为根对象的上下文
	 *
	 * Invokes the internal template methods to create {@code StandardEvaluationContext}
	 * and {@code SecurityExpressionRoot} objects.
	 *
	 * @param authentication the current authentication object
	 * @param invocation the invocation (filter, method, channel)
	 * @return the context object for use in evaluating the expression, populated with a
	 * suitable root object.
	 */
	@Override
	public final EvaluationContext createEvaluationContext(Authentication authentication,
			T invocation) {
		/**
		 * createSecurityExpressionRoot 由子类提供具体实现，根据自己所服务的安全环境创建相应的
		 * SecurityExpressionOperations 对象
		 */
		SecurityExpressionOperations root = createSecurityExpressionRoot(authentication,
				invocation);
		/**
		 * 解析表达式需要的上下文，解析时有一个默认的上下文
		 * 创建	EvaluationContext， 实现类使用标准实现 	StandardEvaluationContext
		 */
		StandardEvaluationContext ctx = createEvaluationContextInternal(authentication,
				invocation);
		// 表达式求值可能需要用到bean，这里指定bean解析器，通常指向整个Spring bean容器
		ctx.setBeanResolver(br);
		// 设置 EvaluationContext 的根对象为上面创建的 SecurityExpressionOperations root
		ctx.setRootObject(root);

		return ctx;
	}

	/**
	 * 一个StandardEvaluationContext或者其子类，缺省是一个StandardEvaluationContext ， 子类可以覆盖该方法提供一个自定义的
	 * StandardEvaluationContext子类实例
	 *
	 * Override to create a custom instance of {@code StandardEvaluationContext}.
	 * <p>
	 * The returned object will have a {@code SecurityExpressionRootPropertyAccessor}
	 * added, allowing beans in the {@code ApplicationContext} to be accessed via
	 * expression properties.
	 *
	 * @param authentication the current authentication object
	 * @param invocation the invocation (filter, method, channel)
	 * @return A {@code StandardEvaluationContext} or potentially a custom subclass if
	 * overridden.
	 */
	protected StandardEvaluationContext createEvaluationContextInternal(
			Authentication authentication, T invocation) {
		return new StandardEvaluationContext();
	}

	/**
	 * Implement in order to create a root object of the correct type for the supported
	 * invocation type.
	 *
	 * @param authentication the current authentication object
	 * @param invocation the invocation (filter, method, channel)
	 * @return the object wh
	 */
	protected abstract SecurityExpressionOperations createSecurityExpressionRoot(
			Authentication authentication, T invocation);

	protected RoleHierarchy getRoleHierarchy() {
		return roleHierarchy;
	}

	public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
		this.roleHierarchy = roleHierarchy;
	}

	protected PermissionEvaluator getPermissionEvaluator() {
		return permissionEvaluator;
	}

	public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
		this.permissionEvaluator = permissionEvaluator;
	}

	public void setApplicationContext(ApplicationContext applicationContext) {
		br = new BeanFactoryResolver(applicationContext);
	}
}
