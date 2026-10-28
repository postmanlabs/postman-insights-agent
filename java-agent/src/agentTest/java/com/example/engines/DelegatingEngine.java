package com.example.engines;

import java.nio.ByteBuffer;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

/**
 * Delegates everything to another engine, as wrapper engines do. In an
 * application package: the agent never instruments its own package.
 */
public final class DelegatingEngine extends SSLEngine {
    private final SSLEngine inner;

    public DelegatingEngine(SSLEngine inner) {
        this.inner = inner;
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int off, int len, ByteBuffer dst) throws SSLException {
        return inner.wrap(srcs, off, len, dst);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int off, int len) throws SSLException {
        return inner.unwrap(src, dsts, off, len);
    }

    @Override
    public Runnable getDelegatedTask() {
        return inner.getDelegatedTask();
    }

    @Override
    public void closeInbound() throws SSLException {
        inner.closeInbound();
    }

    @Override
    public boolean isInboundDone() {
        return inner.isInboundDone();
    }

    @Override
    public void closeOutbound() {
        inner.closeOutbound();
    }

    @Override
    public boolean isOutboundDone() {
        return inner.isOutboundDone();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return inner.getSupportedCipherSuites();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return inner.getEnabledCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        inner.setEnabledCipherSuites(suites);
    }

    @Override
    public String[] getSupportedProtocols() {
        return inner.getSupportedProtocols();
    }

    @Override
    public String[] getEnabledProtocols() {
        return inner.getEnabledProtocols();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        inner.setEnabledProtocols(protocols);
    }

    @Override
    public SSLSession getSession() {
        return inner.getSession();
    }

    @Override
    public void beginHandshake() throws SSLException {
        inner.beginHandshake();
    }

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        return inner.getHandshakeStatus();
    }

    @Override
    public void setUseClientMode(boolean mode) {
        inner.setUseClientMode(mode);
    }

    @Override
    public boolean getUseClientMode() {
        return inner.getUseClientMode();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        inner.setNeedClientAuth(need);
    }

    @Override
    public boolean getNeedClientAuth() {
        return inner.getNeedClientAuth();
    }

    @Override
    public void setWantClientAuth(boolean want) {
        inner.setWantClientAuth(want);
    }

    @Override
    public boolean getWantClientAuth() {
        return inner.getWantClientAuth();
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        inner.setEnableSessionCreation(flag);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return inner.getEnableSessionCreation();
    }
}
