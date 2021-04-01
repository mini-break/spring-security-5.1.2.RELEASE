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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.util.Assert;
import org.springframework.web.filter.DelegatingFilterProxy;

/**
 * * 这个类有点复杂, 因为3个重点类都复用了它, 简述如下
 *   1. 允许将多个安全配置器 SecurityConfigurer 应用到该 SecurityBuilder 上;
 *   2. 定义了构建过程的生命周期(参考生命周期状态定义 BuildState )；
 *   3. 在生命周期基础之上实现并 final 了基类定义的抽象方法 #doBuild, 将构建划分为三个主要阶段#init,#configure,#performBuild;
 *        1. 对 #init/#configure阶段提供了实现;
 *        2. 对 #init/#configure阶段提供了前置回调 #beforeInit/#beforeConfigure 空方法供基类扩展;
 *        3. #performBuild 定义为抽象方法要求子类提供实现；
 *   4. 登记安全构建器工作过程中需要共享使用的一些对象。
 *
 * <p>
 * A base {@link SecurityBuilder} that allows {@link SecurityConfigurer} to be applied to
 * it. This makes modifying the {@link SecurityBuilder} a strategy that can be customized
 * and broken up into a number of {@link SecurityConfigurer} objects that have more
 * specific goals than that of the {@link SecurityBuilder}.
 * </p>
 *
 * <p>
 * For example, a {@link SecurityBuilder} may build an {@link DelegatingFilterProxy}, but
 * a {@link SecurityConfigurer} might populate the {@link SecurityBuilder} with the
 * filters necessary for session management, form based login, authorization, etc.
 * </p>
 *
 * @see WebSecurity
 *
 * @author Rob Winch
 *
 * @param <O> The object that this builder returns
 * @param <B> The type of this builder (that is returned by the base class)
 */
public abstract class AbstractConfiguredSecurityBuilder<O, B extends SecurityBuilder<O>>
		extends AbstractSecurityBuilder<O> {
	private final Log logger = LogFactory.getLog(getClass());

	/**
	 * 所要应用到当前 SecurityBuilder 上的所有的 SecurityConfigurer
	 */
	private final LinkedHashMap<Class<? extends SecurityConfigurer<O, B>>, List<SecurityConfigurer<O, B>>> configurers = new LinkedHashMap<Class<? extends SecurityConfigurer<O, B>>, List<SecurityConfigurer<O, B>>>();

	/**
	 * 用于记录在初始化期间添加进来的 SecurityConfigurer
	 */
	private final List<SecurityConfigurer<O, B>> configurersAddedInInitializing = new ArrayList<SecurityConfigurer<O, B>>();

	/**
	 * 共享对象
	 */
	private final Map<Class<? extends Object>, Object> sharedObjects = new HashMap<Class<? extends Object>, Object>();

	/**
	 * 是否允许相同类型的SecurityConfigurer配置,如果不允许,后面配置的会覆盖前面的配置
	 */
	private final boolean allowConfigurersOfSameType;

	/**
	 * 生命周期状态定义
	 * 初始值为0
	 */
	private BuildState buildState = BuildState.UNBUILT;

	/**
	 * 对象后置处理器，一般用于对象的初始化或者确保对象的销毁方法能够被调用到
	 */
	private ObjectPostProcessor<Object> objectPostProcessor;

	/***
	 * Creates a new instance with the provided {@link ObjectPostProcessor}. This post
	 * processor must support Object since there are many types of objects that may be
	 * post processed.
	 *
	 * @param objectPostProcessor the {@link ObjectPostProcessor} to use
	 */
	protected AbstractConfiguredSecurityBuilder(
			ObjectPostProcessor<Object> objectPostProcessor) {
		// 默认不支持同类型配置
		this(objectPostProcessor, false);
	}

	/***
	 * Creates a new instance with the provided {@link ObjectPostProcessor}. This post
	 * processor must support Object since there are many types of objects that may be
	 * post processed.
	 *
	 * @param objectPostProcessor the {@link ObjectPostProcessor} to use
	 * @param allowConfigurersOfSameType if true, will not override other
	 * {@link SecurityConfigurer}'s when performing apply
	 */
	protected AbstractConfiguredSecurityBuilder(
			ObjectPostProcessor<Object> objectPostProcessor,
			boolean allowConfigurersOfSameType) {
		Assert.notNull(objectPostProcessor, "objectPostProcessor cannot be null");
		this.objectPostProcessor = objectPostProcessor;
		this.allowConfigurersOfSameType = allowConfigurersOfSameType;
	}

	/**
	 * Similar to {@link #build()} and {@link #getObject()} but checks the state to
	 * determine if {@link #build()} needs to be called first.
	 *
	 * @return the result of {@link #build()} or {@link #getObject()}. If an error occurs
	 * while building, returns null.
	 */
	public O getOrBuild() {
		if (isUnbuilt()) {
			try {
				return build();
			}
			catch (Exception e) {
				logger.debug("Failed to perform build. Returning null", e);
				return null;
			}
		}
		else {
			return getObject();
		}
	}

	/**
	 * Applies a {@link SecurityConfigurerAdapter} to this {@link SecurityBuilder} and
	 * invokes {@link SecurityConfigurerAdapter#setBuilder(SecurityBuilder)}.
	 *
	 * @param configurer
	 * @return the {@link SecurityConfigurerAdapter} for further customizations
	 * @throws Exception
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurerAdapter<O, B>> C apply(C configurer)
			throws Exception {
		configurer.addObjectPostProcessor(objectPostProcessor);
		configurer.setBuilder((B) this);
		add(configurer);
		return configurer;
	}

	/**
	 * 应用一个 SecurityConfigurer 到该 SecurityBuilder 上
	 * 
	 * Applies a {@link SecurityConfigurer} to this {@link SecurityBuilder} overriding any
	 * {@link SecurityConfigurer} of the exact same class. Note that object hierarchies
	 * are not considered.
	 *
	 * @param configurer
	 * @return the {@link SecurityConfigurerAdapter} for further customizations
	 * @throws Exception
	 */
	public <C extends SecurityConfigurer<O, B>> C apply(C configurer) throws Exception {
		add(configurer);
		return configurer;
	}

	/**
	 * Sets an object that is shared by multiple {@link SecurityConfigurer}.
	 *
	 * @param sharedType the Class to key the shared object by.
	 * @param object the Object to store
	 */
	@SuppressWarnings("unchecked")
	public <C> void setSharedObject(Class<C> sharedType, C object) {
		this.sharedObjects.put(sharedType, object);
	}

	/**
	 * Gets a shared Object. Note that object heirarchies are not considered.
	 *
	 * @param sharedType the type of the shared Object
	 * @return the shared Object or null if it is not found
	 */
	@SuppressWarnings("unchecked")
	public <C> C getSharedObject(Class<C> sharedType) {
		return (C) this.sharedObjects.get(sharedType);
	}

	/**
	 * Gets the shared objects
	 * @return the shared Objects
	 */
	public Map<Class<? extends Object>, Object> getSharedObjects() {
		return Collections.unmodifiableMap(this.sharedObjects);
	}

	/**
	 * 添加 SecurityConfigurer 到当前 SecurityBuilder 上，添加过程做了同步处理
	 * 
	 * Adds {@link SecurityConfigurer} ensuring that it is allowed and invoking
	 * {@link SecurityConfigurer#init(SecurityBuilder)} immediately if necessary.
	 *
	 * @param configurer the {@link SecurityConfigurer} to add
	 * @throws Exception if an error occurs
	 */
	@SuppressWarnings("unchecked")
	private <C extends SecurityConfigurer<O, B>> void add(C configurer) throws Exception {
		Assert.notNull(configurer, "configurer cannot be null");

		Class<? extends SecurityConfigurer<O, B>> clazz = (Class<? extends SecurityConfigurer<O, B>>) configurer
				.getClass();
		// 同步操作
		synchronized (configurers) {
			if (buildState.isConfigured()) {
				throw new IllegalStateException("Cannot apply " + configurer
						+ " to already built object");
			}
			List<SecurityConfigurer<O, B>> configs = allowConfigurersOfSameType ? this.configurers
					.get(clazz) : null;
			if (configs == null) {
				configs = new ArrayList<SecurityConfigurer<O, B>>(1);
			}
			configs.add(configurer);
			this.configurers.put(clazz, configs);
			// 初始化期间添加进来的配置
			if (buildState.isInitializing()) {
				this.configurersAddedInInitializing.add(configurer);
			}
		}
	}

	/**
	 * Gets all the {@link SecurityConfigurer} instances by its class name or an empty
	 * List if not found. Note that object hierarchies are not considered.
	 *
	 * @param clazz the {@link SecurityConfigurer} class to look for
	 * @return a list of {@link SecurityConfigurer}s for further customization
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurer<O, B>> List<C> getConfigurers(Class<C> clazz) {
		List<C> configs = (List<C>) this.configurers.get(clazz);
		if (configs == null) {
			return new ArrayList<>();
		}
		return new ArrayList<>(configs);
	}

	/**
	 * Removes all the {@link SecurityConfigurer} instances by its class name or an empty
	 * List if not found. Note that object hierarchies are not considered.
	 *
	 * @param clazz the {@link SecurityConfigurer} class to look for
	 * @return a list of {@link SecurityConfigurer}s for further customization
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurer<O, B>> List<C> removeConfigurers(Class<C> clazz) {
		List<C> configs = (List<C>) this.configurers.remove(clazz);
		if (configs == null) {
			return new ArrayList<>();
		}
		return new ArrayList<>(configs);
	}

	/**
	 * Gets the {@link SecurityConfigurer} by its class name or <code>null</code> if not
	 * found. Note that object hierarchies are not considered.
	 *
	 * @param clazz
	 * @return the {@link SecurityConfigurer} for further customizations
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurer<O, B>> C getConfigurer(Class<C> clazz) {
		List<SecurityConfigurer<O, B>> configs = this.configurers.get(clazz);
		if (configs == null) {
			return null;
		}
		if (configs.size() != 1) {
			throw new IllegalStateException("Only one configurer expected for type "
					+ clazz + ", but got " + configs);
		}
		return (C) configs.get(0);
	}

	/**
	 * Removes and returns the {@link SecurityConfigurer} by its class name or
	 * <code>null</code> if not found. Note that object hierarchies are not considered.
	 *
	 * @param clazz
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurer<O, B>> C removeConfigurer(Class<C> clazz) {
		List<SecurityConfigurer<O, B>> configs = this.configurers.remove(clazz);
		if (configs == null) {
			return null;
		}
		if (configs.size() != 1) {
			throw new IllegalStateException("Only one configurer expected for type "
					+ clazz + ", but got " + configs);
		}
		return (C) configs.get(0);
	}

	/**
	 * Specifies the {@link ObjectPostProcessor} to use.
	 * @param objectPostProcessor the {@link ObjectPostProcessor} to use. Cannot be null
	 * @return the {@link SecurityBuilder} for further customizations
	 */
	@SuppressWarnings("unchecked")
	public O objectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
		Assert.notNull(objectPostProcessor, "objectPostProcessor cannot be null");
		this.objectPostProcessor = objectPostProcessor;
		return (O) this;
	}

	/**
	 * Performs post processing of an object. The default is to delegate to the
	 * {@link ObjectPostProcessor}.
	 *
	 * @param object the Object to post process
	 * @return the possibly modified Object to use
	 */
	protected <P> P postProcess(P object) {
		return this.objectPostProcessor.postProcess(object);
	}

	/**
	 * build() 保证对象是单例的
	 * doBuild() 控制创建对象的4个阶段, 其中
	 * #init() 方法, 遍历 configurers 类里面所有的配置对象, 并执行他们的 init(B builder) 方法
	 * #configure() 方法, 遍历 configurers 类里面所有的配置对象, 并执行他们的 configure(B builder) 方法
	 * performBuild() 子类覆盖重写, 用于实际控制 B.build() 返回的对象
	 * 
	 * Executes the build using the {@link SecurityConfigurer}'s that have been applied
	 * using the following steps:
	 *
	 * <ul>
	 * <li>Invokes {@link #beforeInit()} for any subclass to hook into</li>
	 * <li>Invokes {@link SecurityConfigurer#init(SecurityBuilder)} for any
	 * {@link SecurityConfigurer} that was applied to this builder.</li>
	 * <li>Invokes {@link #beforeConfigure()} for any subclass to hook into</li>
	 * <li>Invokes {@link #performBuild()} which actually builds the Object</li>
	 * </ul>
	 */
	@Override
	protected final O doBuild() throws Exception {
		// configurers是通过apply方法添加的
		synchronized (configurers) {
			buildState = BuildState.INITIALIZING;

			// 留给子类拓展
			beforeInit();
			// 调用 configurers 里面每一个 configurer 的 init 方法
			init();

			buildState = BuildState.CONFIGURING;

			// 留给子类拓展
			beforeConfigure();
			// 调用 configurers 里面每一个 configurer 的 configure 方法
			configure();

			buildState = BuildState.BUILDING;

			/**
			 * 子类提供实现
			 * 获取ProviderManager
 			 */
			O result = performBuild();

			buildState = BuildState.BUILT;

			return result;
		}
	}

	/**
	 * Invoked prior to invoking each {@link SecurityConfigurer#init(SecurityBuilder)}
	 * method. Subclasses may override this method to hook into the lifecycle without
	 * using a {@link SecurityConfigurer}.
	 */
	protected void beforeInit() throws Exception {
	}

	/**
	 * Invoked prior to invoking each
	 * {@link SecurityConfigurer#configure(SecurityBuilder)} method. Subclasses may
	 * override this method to hook into the lifecycle without using a
	 * {@link SecurityConfigurer}.
	 */
	protected void beforeConfigure() throws Exception {
	}

	/**
	 * 执行构建逻辑，由子类实现
	 * 
	 * Subclasses must implement this method to build the object that is being returned.
	 *
	 * @return the Object to be buit or null if the implementation allows it
	 */
	protected abstract O performBuild() throws Exception;

	@SuppressWarnings("unchecked")
	private void init() throws Exception {
		Collection<SecurityConfigurer<O, B>> configurers = getConfigurers();
		/**
		 * this指:
		 * 1.WebSecurity
		 * 2.DefaultPasswordEncoderAuthenticationManagerBuilder
		 * 3.HttpSecurity
		 */
		for (SecurityConfigurer<O, B> configurer : configurers) {
			configurer.init((B) this);
		}

		for (SecurityConfigurer<O, B> configurer : configurersAddedInInitializing) {
			configurer.init((B) this);
		}
	}

	@SuppressWarnings("unchecked")
	private void configure() throws Exception {
		Collection<SecurityConfigurer<O, B>> configurers = getConfigurers();

		for (SecurityConfigurer<O, B> configurer : configurers) {
			configurer.configure((B) this);
		}
	}

	private Collection<SecurityConfigurer<O, B>> getConfigurers() {
		List<SecurityConfigurer<O, B>> result = new ArrayList<SecurityConfigurer<O, B>>();
		for (List<SecurityConfigurer<O, B>> configs : this.configurers.values()) {
			result.addAll(configs);
		}
		return result;
	}

	/**
	 * Determines if the object is unbuilt.
	 * @return true, if unbuilt else false
	 */
	private boolean isUnbuilt() {
		synchronized (configurers) {
			return buildState == BuildState.UNBUILT;
		}
	}

	/**
	 * The build state for the application
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	private static enum BuildState {
		/**
		 * This is the state before the {@link Builder#build()} is invoked
		 */
		UNBUILT(0),

		/**
		 * The state from when {@link Builder#build()} is first invoked until all the
		 * {@link SecurityConfigurer#init(SecurityBuilder)} methods have been invoked.
		 */
		INITIALIZING(1),

		/**
		 * The state from after all {@link SecurityConfigurer#init(SecurityBuilder)} have
		 * been invoked until after all the
		 * {@link SecurityConfigurer#configure(SecurityBuilder)} methods have been
		 * invoked.
		 */
		CONFIGURING(2),

		/**
		 * From the point after all the
		 * {@link SecurityConfigurer#configure(SecurityBuilder)} have completed to just
		 * after {@link AbstractConfiguredSecurityBuilder#performBuild()}.
		 */
		BUILDING(3),

		/**
		 * After the object has been completely built.
		 */
		BUILT(4);

		private final int order;

		BuildState(int order) {
			this.order = order;
		}

		/**
		 * 判断是否正在初始化
		 */
		public boolean isInitializing() {
			return INITIALIZING.order == order;
		}

		/**
		 * 判断是否已经配置完毕
		 * Determines if the state is CONFIGURING or later
		 * @return
		 */
		public boolean isConfigured() {
			return order >= CONFIGURING.order;
		}
	}
}
