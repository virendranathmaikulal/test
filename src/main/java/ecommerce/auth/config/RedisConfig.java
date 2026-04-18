package com.ecommerce.auth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * Redis configuration — token store for access, refresh, and reset tokens.
 *
 * Why StringRedisSerializer instead of default JdkSerializationRedisSerializer?
 * - Default serializer stores Java binary objects → keys look like \xac\xed\x00\x05t\x00\x12...
 * - StringRedisSerializer stores plain text → keys look like "user_token:550e8400-..."
 * - Benefits: human-readable in Redis CLI, language-agnostic, smaller payload, no class coupling.
 *
 * Connection pooling is configured in application.yml via Lettuce (Spring Boot 3.x default).
 * Lettuce is non-blocking (Netty-based), thread-safe, and handles pooling natively.
 */
@Slf4j
@Configuration
public class RedisConfig {

    @Bean
    public RedisTemplate<String, String> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, String> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        // All our Redis values are strings (JWTs, UUIDs, token strings)
        StringRedisSerializer serializer = new StringRedisSerializer();
        template.setKeySerializer(serializer);
        template.setValueSerializer(serializer);
        template.setHashKeySerializer(serializer);
        template.setHashValueSerializer(serializer);

        template.afterPropertiesSet();
        log.info("Redis template configured with StringRedisSerializer");
        return template;
    }
}
