package com.ecommerce.auth.dto.response;

import com.ecommerce.auth.constants.AuthConstants;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.time.Instant;

@Getter
@Builder
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> {

    private final int code;
    private final String status;
    private final String message;
    private final T data;

    @Builder.Default
    private final Instant timestamp = Instant.now();

    public static <T> ApiResponse<T> success(HttpStatus httpStatus, String message, T data) {
        return ApiResponse.<T>builder()
                .code(httpStatus.value())
                .status(AuthConstants.RESPONSE_SUCCESS)
                .message(message)
                .data(data)
                .build();
    }

    public static <T> ApiResponse<T> success(HttpStatus httpStatus, String message) {
        return ApiResponse.<T>builder()
                .code(httpStatus.value())
                .status(AuthConstants.RESPONSE_SUCCESS)
                .message(message)
                .build();
    }

    public static <T> ApiResponse<T> error(HttpStatus httpStatus, String message) {
        return ApiResponse.<T>builder()
                .code(httpStatus.value())
                .status(AuthConstants.RESPONSE_ERROR)
                .message(message)
                .build();
    }

    public static <T> ApiResponse<T> error(HttpStatus httpStatus, String message, T data) {
        return ApiResponse.<T>builder()
                .code(httpStatus.value())
                .status(AuthConstants.RESPONSE_ERROR)
                .message(message)
                .data(data)
                .build();
    }
}
