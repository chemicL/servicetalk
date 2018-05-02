/*
 * Copyright © 2018 Apple Inc. and the ServiceTalk project authors
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
package io.servicetalk.http.api;

import io.servicetalk.concurrent.api.Completable;
import io.servicetalk.concurrent.api.Publisher;
import io.servicetalk.concurrent.api.Single;
import io.servicetalk.transport.api.ConnectionContext;

import static io.servicetalk.concurrent.api.Completable.error;
import static io.servicetalk.concurrent.api.Publisher.from;
import static io.servicetalk.http.api.BlockingUtils.blockingToCompletable;
import static java.util.Objects.requireNonNull;

final class BlockingHttpConnectionToHttpConnection<I, O> extends HttpConnection<I, O> {
    private final BlockingHttpConnection<I, O> blockingConnection;

    BlockingHttpConnectionToHttpConnection(BlockingHttpConnection<I, O> blockingConnection) {
        this.blockingConnection = requireNonNull(blockingConnection);
    }

    @Override
    public ConnectionContext getConnectionContext() {
        return blockingConnection.getConnectionContext();
    }

    @Override
    public <T> Publisher<T> getSettingStream(final SettingKey<T> settingKey) {
        return from(getExecutionContext().getExecutor(), blockingConnection.getSettingIterable(settingKey));
    }

    @Override
    public Single<HttpResponse<O>> request(final HttpRequest<I> request) {
        return BlockingUtils.request(blockingConnection, request);
    }

    @Override
    public Completable onClose() {
        if (blockingConnection instanceof HttpConnectionToBlockingHttpConnection) {
            return ((HttpConnectionToBlockingHttpConnection) blockingConnection).onClose();
        }

        return error(new UnsupportedOperationException("unsupported type: " + blockingConnection.getClass()));
    }

    @Override
    public Completable closeAsync() {
        return blockingToCompletable(blockingConnection::close);
    }

    @Override
    BlockingHttpConnection<I, O> asBlockingConnectionInternal() {
        return blockingConnection;
    }
}
