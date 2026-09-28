package com.example.workspace.security;

import com.example.workspace.exception.ApiError;
import com.example.workspace.exception.ErrorCode;
import com.example.workspace.exception.RequestTooLargeException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

// Caps request body size. Two layers, because either alone is bypassable:
//  1. declared Content-Length over the limit -> reject before reading a byte
//  2. otherwise count the bytes actually read and fail once over the limit,
//     which also covers chunked requests (no Content-Length) and clients
//     that declare a small length and send more
//
// Known limit: a future file-upload endpoint will need a larger cap than
// this JSON one. Add a path-based override when that endpoint exists.
@Component
public class RequestSizeLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RequestSizeLimitFilter.class);

    private final long maxBytes;
    private final ObjectMapper objectMapper;

    // ObjectMapper is Spring's own bean, not a hand-built one. A separate
    // instance formats Instants differently (the bug from the entry point).
    public RequestSizeLimitFilter(@Value("${app.limits.max-request-body}") DataSize maxBody,
                                  ObjectMapper objectMapper) {
        this.maxBytes = maxBody.toBytes();
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        long declared = request.getContentLengthLong(); // -1 when unknown (chunked)

        if (declared > maxBytes) {
            log.warn("Request body too large: path={} declaredBytes={} limit={}",
                    request.getRequestURI(), declared, maxBytes);
            ApiError body = ApiError.of(ErrorCode.PAYLOAD_TOO_LARGE, request.getRequestURI());
            response.setStatus(ErrorCode.PAYLOAD_TOO_LARGE.getHttpStatus().value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(objectMapper.writeValueAsString(body));
            return;
        }

        filterChain.doFilter(new LimitedRequest(request, maxBytes), response);
    }

    private static final class LimitedRequest extends HttpServletRequestWrapper {
        private final long max;
        private ServletInputStream stream;

        LimitedRequest(HttpServletRequest request, long max) {
            super(request);
            this.max = max;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (stream == null) {
                stream = new CountingInputStream(super.getInputStream(), max);
            }
            return stream;
        }

        @Override
        public BufferedReader getReader() throws IOException {
            // route the reader through our counted stream too, otherwise
            // anything calling getReader() would skip the limit
            String encoding = getCharacterEncoding();
            Charset charset = encoding != null ? Charset.forName(encoding) : StandardCharsets.UTF_8;
            return new BufferedReader(new InputStreamReader(getInputStream(), charset));
        }
    }

    private static final class CountingInputStream extends ServletInputStream {
        private final ServletInputStream delegate;
        private final long max;
        private long count;

        CountingInputStream(ServletInputStream delegate, long max) {
            this.delegate = delegate;
            this.max = max;
        }

        @Override
        public int read() throws IOException {
            int b = delegate.read();
            if (b != -1) count(1);
            return b;
        }

        @Override
        public int read(byte[] buf, int off, int len) throws IOException {
            int n = delegate.read(buf, off, len);
            if (n > 0) count(n);
            return n;
        }

        private void count(long n) throws IOException {
            count += n;
            if (count > max) throw new RequestTooLargeException(max);
        }

        @Override public boolean isFinished() { return delegate.isFinished(); }
        @Override public boolean isReady() { return delegate.isReady(); }
        @Override public void setReadListener(ReadListener listener) { delegate.setReadListener(listener); }
    }
}