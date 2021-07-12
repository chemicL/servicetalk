/*
 * Copyright © 2021 Apple Inc. and the ServiceTalk project authors
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
package io.servicetalk.grpc.netty;

import io.servicetalk.concurrent.internal.ServiceTalkTestTimeout;
import io.servicetalk.grpc.api.GrpcClientBuilder;
import io.servicetalk.grpc.api.GrpcStatusException;
import io.servicetalk.grpc.netty.TesterProto.Tester.BlockingTesterClient;
import io.servicetalk.logging.api.LogLevel;
import io.servicetalk.test.resources.DefaultTestCerts;
import io.servicetalk.transport.api.ClientSslConfigBuilder;
import io.servicetalk.transport.api.HostAndPort;
import io.servicetalk.transport.api.ServerContext;
import io.servicetalk.transport.api.ServerSslConfig;
import io.servicetalk.transport.api.ServerSslConfigBuilder;
import io.servicetalk.transport.netty.internal.StacklessClosedChannelException;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import javax.annotation.Nonnull;
import javax.net.ssl.SSLHandshakeException;

import static io.servicetalk.grpc.netty.ExecutionStrategyTestServices.DEFAULT_STRATEGY_ASYNC_SERVICE;
import static io.servicetalk.test.resources.DefaultTestCerts.serverPemHostname;
import static io.servicetalk.transport.api.SslProvider.JDK;
import static io.servicetalk.transport.api.SslProvider.OPENSSL;
import static io.servicetalk.transport.netty.internal.AddressUtils.localAddress;
import static io.servicetalk.transport.netty.internal.AddressUtils.serverHostAndPort;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonMap;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThrows;

public class GrpcSslAndNonSslConnectionsTest {

    private static final String SNI_HOSTNAME = "servicetalk.io";
    private static final TesterProto.TestRequest REQUEST = TesterProto.TestRequest.newBuilder().setName("test").build();

    @Rule
    public final Timeout timeout = new ServiceTalkTestTimeout();

    private ServerContext grpcServer(TesterProto.Tester.ServiceFactory... serviceFactories) throws Exception {
        return GrpcServers.forAddress(localAddress(0))
                .listenAndAwait(serviceFactories);
    }

    private ServerContext secureGrpcServer(TesterProto.Tester.ServiceFactory... serviceFactories)
            throws Exception {
        return GrpcServers.forAddress(localAddress(0))
                .sslConfig(
                        trustedServerConfig()
                )
                .listenAndAwait(serviceFactories);
    }

    private GrpcClientBuilder<HostAndPort, InetSocketAddress> secureGrpcClient(
            final ServerContext serverContext, final ClientSslConfigBuilder sslConfigBuilder) {
        return GrpcClients.forAddress(serverHostAndPort(serverContext))
                .sslConfig(
                        sslConfigBuilder.build()
                );
    }

    private BlockingTesterClient grpcClient(ServerContext serverContext) {
        return GrpcClients.forAddress(serverHostAndPort(serverContext))
                .buildBlocking(clientFactory());
    }

    private TesterProto.Tester.ClientFactory clientFactory() {
        return new TesterProto.Tester.ClientFactory();
    }

    private TesterProto.Tester.ServiceFactory serviceFactory() {
        return new TesterProto.Tester.ServiceFactory.Builder()
                .test(DEFAULT_STRATEGY_ASYNC_SERVICE)
                .build();
    }

    private static ServerSslConfig untrustedServerConfig() {
        // Need a key that won't be trusted by the client, just use the client's key.
        return new ServerSslConfigBuilder(DefaultTestCerts::loadClientPem,
                DefaultTestCerts::loadClientKey)
                .sslProtocols("TLSv1_3")
                .alpnProtocols()
                .provider(OPENSSL).build();
    }

    @Test
    public void connectingToSecureServerWithSecureClient() throws Exception {
        try (ServerContext serverContext = secureGrpcServer(serviceFactory());
             BlockingTesterClient client = secureGrpcClient(serverContext,
                     new ClientSslConfigBuilder(DefaultTestCerts::loadServerCAPem)
                             .peerHost(serverPemHostname()))
                     .buildBlocking(clientFactory())) {
            final TesterProto.TestResponse response = client.test(REQUEST);
            assertThat(response, is(notNullValue()));
            assertThat(response.getMessage(), is(notNullValue()));
        }
    }

    @Test
    public void secureClientToNonSecureServerClosesConnection() throws Exception {
        try (ServerContext serverContext = grpcServer(serviceFactory());
             BlockingTesterClient client = secureGrpcClient(serverContext,
                     new ClientSslConfigBuilder(DefaultTestCerts::loadServerCAPem)
                             .peerHost(serverPemHostname()))
                     .buildBlocking(clientFactory())) {
            GrpcStatusException e = assertThrows(GrpcStatusException.class, () -> client.test(REQUEST));
            assertThat(e.getCause(), instanceOf(SSLHandshakeException.class));
        }
    }

    @Test
    public void nonSecureClientToSecureServerClosesConnection() throws Exception {
        try (ServerContext serverContext = secureGrpcServer(serviceFactory());
             BlockingTesterClient client = grpcClient(serverContext)) {
            GrpcStatusException e = assertThrows(GrpcStatusException.class, () -> client.test(REQUEST));
            assertThat(e.getCause(), instanceOf(StacklessClosedChannelException.class));
        }
    }

    @Test
    public void secureClientToSecureServerWithoutPeerHost() throws Exception {
        try (ServerContext serverContext = secureGrpcServer(serviceFactory());
             BlockingTesterClient client = secureGrpcClient(serverContext,
                     new ClientSslConfigBuilder(DefaultTestCerts::loadServerCAPem)
                             .peerHost(null)
                             // if verification is not disabled, identity check fails against the undefined address
                             .hostnameVerificationAlgorithm(""))
                     .inferPeerHost(false)
                     .buildBlocking(clientFactory())) {
            final TesterProto.TestResponse response = client.test(REQUEST);
            assertThat(response, is(notNullValue()));
            assertThat(response.getMessage(), is(notNullValue()));
        }
    }

    @Test
    public void noSniClientDefaultServerFallbackSuccess() throws Exception {
        try (ServerContext serverContext = GrpcServers.forAddress(localAddress(0))
                .sslConfig(
                        trustedServerConfig(),
                        emptyMap()
                        // singletonMap("localhost", untrustedServerConfig())
                )
                .enableWireLogging("SERVER", LogLevel.INFO, () -> true)
                .listenAndAwait(serviceFactory());
             // BlockingTesterClient client = secureGrpcClient(serverContext,
             //         new ClientSslConfigBuilder(DefaultTestCerts::loadServerCAPem)
             //                 .peerHost(serverPemHostname()))
             //         .buildBlocking(clientFactory())
             // BlockingTesterClient client = secureGrpcClient(serverContext, new ClientSslConfigBuilder(DefaultTestCerts::loadServerCAPem)
             //         .peerHost(serverPemHostname())).buildBlocking(clientFactory())
             BlockingTesterClient client = GrpcClients.forAddress(
                     InetAddress.getLoopbackAddress().getHostName(), serverHostAndPort(serverContext).port())
                     .sslConfig(
                             new ClientSslConfigBuilder(DefaultTestCerts::loadServerCAPem)
                                     // .peerHost(serverPemHostname()).hostnameVerificationAlgorithm("").build()
                                     .peerHost(null).hostnameVerificationAlgorithm("").sslProtocols("TLSv1.3").provider(OPENSSL).build()
                     ).enableWireLogging("CLIENT", LogLevel.INFO, () -> true)
                     .inferSniHostname(false)
                     .inferPeerHost(false)
                     .buildBlocking(clientFactory())
        ) {
            final TesterProto.TestResponse response = client.test(REQUEST);
            assertThat(response, is(notNullValue()));
            assertThat(response.getMessage(), is(notNullValue()));
        }
    }

    @Nonnull
    private ServerSslConfig trustedServerConfig() {
        return new ServerSslConfigBuilder(DefaultTestCerts::loadServerPem, DefaultTestCerts::loadServerKey)
                .sslProtocols("TLSv1.3")
                .provider(OPENSSL)
                .build();
    }

    @Test
    public void noSniClientDefaultServerFallbackFailExpected() throws Exception {

    }
}
