package com.enterprise.gatekeeper.gatekeeper_service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitingFilter.class);
    private final Cache<String, Bucket> cache = Caffeine.newBuilder().expireAfterAccess(10, TimeUnit.MINUTES).build();

    private Bucket createNewBucket() {
        // Policy: Maximum capacity of 20 requests, refilling 10 tokens every 1 minute
        return Bucket.builder().addLimit(limit -> limit.capacity(20).refillIntervally(10, Duration.ofMinutes(1))).build();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        String clientIp = request.getRemoteAddr();
        // 3. Fetch or compute the IP's respective bucket
        Bucket bucket = cache.get(clientIp, key -> createNewBucket());
        if (bucket.tryConsume(1)) {
            // Token successfully deducted; pass transaction down the line
            filterChain.doFilter(request, response);
        } else {
            // Bucket depleted; issue immediate short-circuit block
            logger.warn("[SECURITY FIREWALL] Rate limit exceeded by IP: {} attempting to hit {}", clientIp, path);

            response.setStatus(429); // Standard HTTP status for Too Many Requests
            response.setContentType("text/plain");
            response.getWriter().write("Too many requests. Please slow down and retry later.");
        }
    }
}
