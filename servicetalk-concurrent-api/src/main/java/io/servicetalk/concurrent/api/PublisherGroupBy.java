/*
 * Copyright © 2018, 2021 Apple Inc. and the ServiceTalk project authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.servicetalk.concurrent.api;

import java.util.function.Function;
import javax.annotation.Nullable;

import static java.util.Objects.requireNonNull;

/**
 * {@link Publisher} as returned by {@link Publisher#groupBy(Function, int)} and its variants.
 * @param <Key> The type of key which identifies a {@link GroupedPublisher}.
 * @param <T> Type of elements emitted by the {@link GroupedPublisher}s emitted by this {@link Publisher}.
 */
final class PublisherGroupBy<Key, T> extends AbstractPublisherGroupBy<Key, T> {
    private final Function<? super T, ? extends Key> keySelector;

    PublisherGroupBy(Publisher<T> original, Function<? super T, ? extends Key> keySelector, int queueLimit) {
        super(original, queueLimit);
        this.keySelector = requireNonNull(keySelector);
    }

    PublisherGroupBy(Publisher<T> original, Function<? super T, ? extends Key> keySelector, int queueLimit,
                     int expectedGroupCountHint) {
        super(original, queueLimit, expectedGroupCountHint);
        this.keySelector = requireNonNull(keySelector);
    }

    @Override
    void handleSubscribe(Subscriber<? super GroupedPublisher<Key, T>> subscriber,
                         AsyncContextMap contextMap, AsyncContextProvider contextProvider) {
        original.delegateSubscribe(new GroupBySubscriber(subscriber, queueLimit, initialCapacityForGroups, contextMap,
                contextProvider), contextMap, contextProvider);
    }

    private final class GroupBySubscriber extends AbstractGroupBySubscriber<Key, T> {
        GroupBySubscriber(final Subscriber<? super GroupedPublisher<Key, T>> target, final int maxQueueSize,
                          final int initialCapacityForGroups, final AsyncContextMap contextMap,
                          final AsyncContextProvider contextProvider) {
            super(target, maxQueueSize, initialCapacityForGroups, contextMap, contextProvider);
        }

        @Override
        public void onNext(@Nullable final T t) {
            onNext(requireNonNull(keySelector.apply(t)), t);
        }
    }
}
