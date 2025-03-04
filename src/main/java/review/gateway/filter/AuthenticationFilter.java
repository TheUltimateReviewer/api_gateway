package review.gateway.filter;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import java.util.List;

@Component
public class AuthenticationFilter implements GlobalFilter {

    @Autowired
    private WebClient.Builder webClientBuilder;

    // Rutas públicas que no requieren autenticación
    private static final List<String> EXCLUDED_PATHS = List.of(
            "/api/auth/login",
            "/api/auth/register"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // Si la ruta es pública, continuar sin validar JWT
        if (EXCLUDED_PATHS.contains(path)) {
            return chain.filter(exchange);
        }

        // Si no hay token, rechazar con 401 Unauthorized
        List<String> authHeaders = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION);
        if (authHeaders == null || authHeaders.isEmpty()) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeaders.get(0);

        // Validar el token llamando al servicio de autenticación
        return webClientBuilder.build()
                .get()
                .uri("http://AUTH-SERVICE/api/auth/validate?token=" + token)
                .retrieve()
                .bodyToMono(TokenValidationResponse.class)
                .flatMap(response -> {
                    if (!response.isValid()) {
                        // Si el token no es válido, rechazar con 401 Unauthorized
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    }

                    // ✅ Si el token es válido, pasar roles y permisos a los headers
                    exchange.getRequest().mutate()
                            .header("X-User-Role", response.getRole().get(0).getAuthority())
                            .header("X-User-Permissions", String.join(",", response.getPermissions()))
                            .build();

                    return chain.filter(exchange);
                })
                .onErrorResume(error -> {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                });
    }

    private static class TokenValidationResponse {
        private List<Role> role;
        private String username;
        private List<String> permissions;
        private boolean valid;

        public List<Role> getRole() { return role; }
        public String getUsername() { return username; }
        public List<String> getPermissions() { return permissions; }
        public boolean isValid() { return valid; }

        private static class Role {
            private String authority;
            public String getAuthority() { return authority; }
        }
    }

}
