/*
 * Copyright © 2021-2022 Apple Inc. and the ServiceTalk project authors
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
package io.servicetalk.http.utils;

import io.servicetalk.buffer.api.Buffer;
import io.servicetalk.concurrent.TimeSource;
import io.servicetalk.concurrent.api.DefaultThreadFactory;
import io.servicetalk.concurrent.api.Executor;
import io.servicetalk.concurrent.api.Executors;
import io.servicetalk.concurrent.api.Publisher;
import io.servicetalk.concurrent.api.Single;
import io.servicetalk.concurrent.api.TestPublisher;
import io.servicetalk.concurrent.api.TestSingle;
import io.servicetalk.concurrent.api.test.StepVerifiers;
import io.servicetalk.http.api.DefaultHttpHeadersFactory;
import io.servicetalk.http.api.EmptyHttpHeaders;
import io.servicetalk.http.api.HttpExecutionStrategies;
import io.servicetalk.http.api.HttpExecutionStrategy;
import io.servicetalk.http.api.HttpRequestMetaData;
import io.servicetalk.http.api.StreamingHttpResponse;
import io.servicetalk.transport.api.IoExecutor;
import io.servicetalk.transport.api.IoThreadFactory;
import io.servicetalk.transport.netty.NettyIoExecutors;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;

import static io.servicetalk.buffer.netty.BufferAllocators.DEFAULT_ALLOCATOR;
import static io.servicetalk.concurrent.api.Executors.immediate;
import static io.servicetalk.concurrent.api.Single.succeeded;
import static io.servicetalk.concurrent.internal.TimeoutTracingInfoExtension.DEFAULT_TIMEOUT_SECONDS;
import static io.servicetalk.http.api.HttpExecutionStrategies.defaultStrategy;
import static io.servicetalk.http.api.HttpExecutionStrategies.offloadAll;
import static io.servicetalk.http.api.HttpExecutionStrategies.offloadNever;
import static io.servicetalk.http.api.HttpExecutionStrategies.offloadNone;
import static io.servicetalk.http.api.HttpProtocolVersion.HTTP_1_1;
import static io.servicetalk.http.api.HttpResponseStatus.OK;
import static io.servicetalk.http.api.StreamingHttpResponses.newResponse;
import static java.lang.Long.MAX_VALUE;
import static java.time.Duration.ZERO;
import static java.time.Duration.ofMillis;
import static java.time.Duration.ofNanos;
import static java.time.Duration.ofSeconds;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

abstract class AbstractTimeoutHttpFilterTest {

    private static final String EXECUTOR_NAME_PREFIX = "Timeout-Executor";
    protected static final Executor EXECUTOR = Executors.newCachedThreadExecutor(
            new DefaultThreadFactory(EXECUTOR_NAME_PREFIX));
    protected static final IoExecutor IO_EXECUTOR = NettyIoExecutors.createIoExecutor("Timeout-IoExecutor");

    abstract void newFilter(Duration duration);

    abstract Single<StreamingHttpResponse> applyFilter(Duration duration, boolean fullRequestResponse,
                                                       HttpExecutionStrategy strategy,
                                                       Single<StreamingHttpResponse> responseSingle);

    abstract Single<StreamingHttpResponse> applyFilter(
            BiFunction<HttpRequestMetaData, TimeSource, Duration> timeoutForRequest,
            boolean fullRequestResponse,
            HttpExecutionStrategy strategy,
            Single<StreamingHttpResponse> responseSingle);

    @Test
    void constructorValidatesDuration() {
        //noinspection ConstantConditions
        assertThrows(NullPointerException.class, () -> newFilter(null));
        assertThrows(IllegalArgumentException.class, () -> newFilter(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> newFilter(ofNanos(1L).negated()));
    }

    @ParameterizedTest(name = "{index}: fullRequestResponse={0}")
    @ValueSource(booleans = {false, true})
    void responseTimeout(boolean fullRequestResponse) {
        TestSingle<StreamingHttpResponse> responseSingle = new TestSingle<>();
        StepVerifiers.create(applyFilter(ofNanos(1L), fullRequestResponse, defaultStrategy(), responseSingle))
                .expectError(TimeoutException.class)
                .verify();
        assertThat("No subscribe for response single", responseSingle.isSubscribed(), is(true));
    }

    @ParameterizedTest(name = "{index}: fullRequestResponse={0}")
    @ValueSource(booleans = {false, true})
    void responseWithZeroTimeout(boolean fullRequestResponse) {
        responseWithNonPositiveTimeout(ZERO, fullRequestResponse);
    }

    @ParameterizedTest(name = "{index}: fullRequestResponse={0}")
    @ValueSource(booleans = {false, true})
    void responseWithNegativeTimeout(boolean fullRequestResponse) {
        responseWithNonPositiveTimeout(ofNanos(1L).negated(), fullRequestResponse);
    }

    private void responseWithNonPositiveTimeout(Duration timeout, boolean fullRequestResponse) {
        TestSingle<StreamingHttpResponse> responseSingle = new TestSingle<>();
        StepVerifiers.create(applyFilter((req, ts) -> timeout, fullRequestResponse, defaultStrategy(), responseSingle))
                .expectError(TimeoutException.class)
                .verify();
        assertThat("No subscribe for payload body", responseSingle.isSubscribed(), is(true));
    }

    @ParameterizedTest(name = "{index}: fullRequestResponse={0}")
    @ValueSource(booleans = {false, true})
    void responseCompletesBeforeTimeout(boolean fullRequestResponse) {
        TestSingle<StreamingHttpResponse> responseSingle = new TestSingle<>();
        StepVerifiers.create(applyFilter(ofSeconds(DEFAULT_TIMEOUT_SECONDS / 2),
                        fullRequestResponse, defaultStrategy(), responseSingle))
                .then(() -> immediate().schedule(() -> {
                            StreamingHttpResponse response = mock(StreamingHttpResponse.class);
                            when(response.transformMessageBody(any())).thenReturn(response);
                            responseSingle.onSuccess(response);
                        },
                        ofMillis(50L)))
                .expectSuccess()
                .verify();
        assertThat("No subscribe for response single", responseSingle.isSubscribed(), is(true));
    }

    static Iterable<HttpExecutionStrategy> executionStrategies() {
        return Arrays.asList(offloadNever(), offloadNone(),
                HttpExecutionStrategies.customStrategyBuilder().offloadEvent().build(),
                defaultStrategy(), offloadAll());
    }

    @ParameterizedTest(name = "{index}: strategy={0}")
    @MethodSource("executionStrategies")
    void payloadBodyTimeout(HttpExecutionStrategy strategy) {
        TestPublisher<Buffer> payloadBody = new TestPublisher<>();
        AtomicBoolean responseSucceeded = new AtomicBoolean();
        StepVerifiers.create(applyFilter(ofMillis(100L), true, strategy, responseWith(payloadBody))
                    .whenOnSuccess(__ -> responseSucceeded.set(true))
                    .flatMapPublisher(StreamingHttpResponse::payloadBody))
                .thenRequest(MAX_VALUE)
                .expectErrorMatches(t -> TimeoutException.class.isInstance(t) &&
                        (Thread.currentThread() instanceof IoThreadFactory.IoThread ^ strategy.hasOffloads()))
                .verify();
        assertThat("Response did not succeeded", responseSucceeded.get(), is(true));
        assertThat("No subscribe for payload body", payloadBody.isSubscribed(), is(true));
    }

    @Test
    void payloadBodyDoesNotTimeoutWhenIgnored() {
        Duration timeout = ofMillis(100L);
        TestPublisher<Buffer> payloadBody = new TestPublisher<>();
        AtomicBoolean responseSucceeded = new AtomicBoolean();
        StepVerifiers.create(applyFilter(timeout, false, defaultStrategy(), responseWith(payloadBody))
                    .whenOnSuccess(__ -> responseSucceeded.set(true))
                    .flatMapPublisher(StreamingHttpResponse::payloadBody))
                .expectSubscriptionConsumed(subscription ->
                        immediate().schedule(subscription::cancel, timeout.plusMillis(10L)))
                .thenRequest(MAX_VALUE)
                .expectNoSignals(timeout.plusMillis(5L))
                // FIXME: use thenCancel() instead of expectSubscriptionConsumed(...) + expectError()
                // https://github.com/apple/servicetalk/issues/1492
                .expectError(IllegalStateException.class)   // should never happen
                .verify();
        assertThat("Response did not succeeded", responseSucceeded.get(), is(true));
        assertThat("No subscribe for payload body", payloadBody.isSubscribed(), is(true));
    }

    @Test
    void subscribeToPayloadBodyAfterTimeout() {
        Duration timeout = ofMillis(100L);
        TestPublisher<Buffer> payloadBody = new TestPublisher<>();
        AtomicReference<StreamingHttpResponse> response = new AtomicReference<>();
        StepVerifiers.create(applyFilter(timeout, true,
                        defaultStrategy(), responseWith(payloadBody)))
                .expectSuccessConsumed(response::set)
                .verify();

        // Subscribe to payload body after timeout
        StepVerifiers.create(immediate().timer(timeout.plusMillis(5L)).concat(response.get().payloadBody()))
                .expectError(TimeoutException.class)
                .verify();
        assertThat("No subscribe for payload body", payloadBody.isSubscribed(), is(true));
    }

    @Test
    void payloadBodyCompletesBeforeTimeout() {
        TestPublisher<Buffer> payloadBody = new TestPublisher<>();
        AtomicReference<StreamingHttpResponse> response = new AtomicReference<>();
        StepVerifiers.create(applyFilter(ofSeconds(DEFAULT_TIMEOUT_SECONDS / 2),
                        true, defaultStrategy(), responseWith(payloadBody)))
                .expectSuccessConsumed(response::set)
                .verify();

        StepVerifiers.create(response.get().payloadBody())
                .then(() -> immediate().schedule(payloadBody::onComplete, ofMillis(50L)))
                .expectComplete()
                .verify();
        assertThat("No subscribe for payload body", payloadBody.isSubscribed(), is(true));
    }

    private static Single<StreamingHttpResponse> responseWith(Publisher<Buffer> payloadBody) {
        return succeeded(newResponse(OK, HTTP_1_1, EmptyHttpHeaders.INSTANCE, DEFAULT_ALLOCATOR,
                DefaultHttpHeadersFactory.INSTANCE).payloadBody(payloadBody));
    }
}
