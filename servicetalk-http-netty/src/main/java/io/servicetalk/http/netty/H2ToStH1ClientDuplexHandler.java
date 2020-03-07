/*
 * Copyright © 2019-2020 Apple Inc. and the ServiceTalk project authors
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
package io.servicetalk.http.netty;

import io.servicetalk.buffer.api.Buffer;
import io.servicetalk.buffer.api.BufferAllocator;
import io.servicetalk.http.api.HttpHeaders;
import io.servicetalk.http.api.HttpHeadersFactory;
import io.servicetalk.http.api.HttpRequestMetaData;
import io.servicetalk.http.api.HttpRequestMethod;
import io.servicetalk.http.api.HttpResponseStatus;
import io.servicetalk.http.api.StreamingHttpResponse;
import io.servicetalk.transport.netty.internal.CloseHandler;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpScheme;
import io.netty.handler.codec.http2.DefaultHttp2HeadersFrame;
import io.netty.handler.codec.http2.Http2DataFrame;
import io.netty.handler.codec.http2.Http2Headers;
import io.netty.handler.codec.http2.Http2HeadersFrame;

import javax.annotation.Nullable;

import static io.netty.handler.codec.http2.Http2Headers.PseudoHeaderName.STATUS;
import static io.servicetalk.http.api.HttpHeaderNames.CONTENT_LENGTH;
import static io.servicetalk.http.api.HttpHeaderNames.HOST;
import static io.servicetalk.http.api.HttpHeaderValues.ZERO;
import static io.servicetalk.http.api.HttpProtocolVersion.HTTP_2_0;
import static io.servicetalk.http.api.HttpRequestMethod.CONNECT;
import static io.servicetalk.http.api.HttpResponseStatus.StatusClass.INFORMATIONAL_1XX;
import static io.servicetalk.http.api.StreamingHttpResponses.newResponse;
import static io.servicetalk.http.netty.H2ToStH1Utils.h1HeadersToH2Headers;
import static io.servicetalk.http.netty.H2ToStH1Utils.h2HeadersSanitizeForH1;
import static io.servicetalk.http.netty.HeaderUtils.canAddResponseTransferEncodingProtocol;
import static io.servicetalk.http.netty.HeaderUtils.shouldAddZeroContentLength;

final class H2ToStH1ClientDuplexHandler extends AbstractH2DuplexHandler {
    private boolean readHeaders;
    private final HttpScheme scheme;
    @Nullable
    private HttpRequestMethod method;

    H2ToStH1ClientDuplexHandler(boolean sslEnabled, BufferAllocator allocator, HttpHeadersFactory headersFactory,
                                CloseHandler closeHandler) {
        super(allocator, headersFactory, closeHandler);
        this.scheme = sslEnabled ? HttpScheme.HTTPS : HttpScheme.HTTP;
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
        if (msg instanceof HttpRequestMetaData) {
            HttpRequestMetaData metaData = (HttpRequestMetaData) msg;
            HttpHeaders h1Headers = metaData.headers();
            CharSequence host = h1Headers.getAndRemove(HOST);
            Http2Headers h2Headers = h1HeadersToH2Headers(h1Headers);
            if (host == null) {
                host = metaData.effectiveHost();
                if (host != null) {
                    h2Headers.authority(host);
                }
            } else {
                h2Headers.authority(host);
            }
            method = metaData.method();
            h2Headers.method(method.name());
            if (!CONNECT.equals(method)) {
                // The ":scheme" and ":path" pseudo-header fields MUST be omitted for CONNECT.
                // https://tools.ietf.org/html/rfc7540#section-8.3
                h2Headers.scheme(scheme.name());
                h2Headers.path(metaData.requestTarget());
            }
            ctx.write(new DefaultHttp2HeadersFrame(h2Headers, false), promise);
        } else if (msg instanceof Buffer) {
            writeBuffer(ctx, msg, promise);
        } else if (msg instanceof HttpHeaders) {
            writeTrailers(ctx, msg, promise);
        } else {
            ctx.write(msg, promise);
        }
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof Http2HeadersFrame) {
            Http2HeadersFrame headersFrame = (Http2HeadersFrame) msg;
            Http2Headers h2Headers = headersFrame.headers();
            final HttpResponseStatus httpStatus;
            if (!readHeaders) {
                CharSequence status = h2Headers.getAndRemove(STATUS.value());
                if (status == null) {
                    throw new IllegalArgumentException("a response must have " + STATUS + " header");
                }
                httpStatus = HttpResponseStatus.of(status);
                if (httpStatus.statusClass().equals(INFORMATIONAL_1XX)) {
                    // We don't expose 1xx "interim responses" [2] to the user, and discard them to make way for the
                    // "real" response.
                    //
                    // for a response only, zero or more HEADERS frames (each followed
                    //        by zero or more CONTINUATION frames) containing the message
                    //        headers of informational (1xx) HTTP responses. [1]
                    // A client MUST be able to parse one or more 1xx responses received
                    //    prior to a final response, even if the client does not expect one.  A
                    //    user agent MAY ignore unexpected 1xx responses. [2]
                    // 1xx responses are terminated by the first empty line after
                    //    the status-line (the empty line signaling the end of the header
                    //    section). [2]
                    // [1] https://tools.ietf.org/html/rfc7540#section-8.1
                    // [2] https://tools.ietf.org/html/rfc7231#section-6.2
                    return;
                }
                readHeaders = true;
            } else {
                httpStatus = null;
            }

            if (headersFrame.isEndStream()) {
                if (httpStatus != null) {
                    fireFullResponse(ctx, h2Headers, httpStatus);
                } else {
                    ctx.fireChannelRead(h2HeadersToH1HeadersClient(h2Headers, null));
                }
            } else if (httpStatus == null) {
                throw new IllegalArgumentException("a response must have " + STATUS + " header");
            } else {
                StreamingHttpResponse response = newResponse(httpStatus, HTTP_2_0,
                        h2HeadersToH1HeadersClient(h2Headers, httpStatus), allocator, headersFactory);
                ctx.fireChannelRead(response);
            }
        } else if (msg instanceof Http2DataFrame) {
            readDataFrame(ctx, msg);
        } else {
            ctx.fireChannelRead(msg);
        }
    }

    private void fireFullResponse(ChannelHandlerContext ctx, final Http2Headers h2Headers,
                                  HttpResponseStatus httpStatus) {
        assert method != null;
        if (shouldAddZeroContentLength(httpStatus.code(), method)) {
            h2Headers.set(CONTENT_LENGTH, ZERO);
        }
        StreamingHttpResponse response = newResponse(httpStatus, HTTP_2_0,
                h2HeadersToH1HeadersClient(h2Headers, httpStatus), allocator, headersFactory);
        ctx.fireChannelRead(response);
        ctx.fireChannelRead(headersFactory.newEmptyTrailers());
    }

    private NettyH2HeadersToHttpHeaders h2HeadersToH1HeadersClient(Http2Headers h2Headers,
                                                                   @Nullable HttpResponseStatus httpStatus) {
        assert method != null;
        h2HeadersSanitizeForH1(h2Headers);
        if (httpStatus != null && !h2Headers.contains(HttpHeaderNames.CONTENT_LENGTH) &&
                canAddResponseTransferEncodingProtocol(httpStatus.code(), method)) {
            h2Headers.add(HttpHeaderNames.TRANSFER_ENCODING, HttpHeaderValues.CHUNKED);
        }
        return new NettyH2HeadersToHttpHeaders(h2Headers, headersFactory.validateCookies());
    }
}
