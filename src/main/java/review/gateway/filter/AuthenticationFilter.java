package review.gateway.filter;



import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import review.gateway.Services.JwtUtil;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class AuthenticationFilter implements GlobalFilter {

    @Autowired
    private JwtUtil jwtUtil;

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

        // Extraer el header de autorización
        List<String> authHeaders = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION);
        if (authHeaders == null || authHeaders.isEmpty()) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Se espera que el token venga con el prefijo "Bearer "
        String token = authHeaders.get(0);
        if (token.startsWith("Bearer ")) {
            token = token.substring(7);
        }

        // Validar el token
        if (!jwtUtil.isTokenValid(token)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Extraer claims
        Claims claims = jwtUtil.getClaimsFromToken(token);
        if (claims != null) {
            String username = claims.getSubject();
            Integer userIdInt = claims.get("user_id", Integer.class);
            String userId = userIdInt != null ? String.valueOf(userIdInt) : "";
            Integer profileIdInt = claims.get("profile_id", Integer.class);
            String profileId = profileIdInt != null ? String.valueOf(profileIdInt) : "";

            // Se asume que roles y permisos fueron agregados como listas al generar el token
            List<String> roles = claims.get("roles", List.class);
            List<String> permissions = claims.get("permissions", List.class);

            Object rolesObj = claims.get("roles");
            String rolesHeader = "";
            if (rolesObj instanceof List<?>) {
                List<?> rolesList = (List<?>) rolesObj;
                rolesHeader = rolesList.stream()
                        .map(role -> {
                            if (role instanceof String) {
                                return (String) role;
                            } else if (role instanceof Map<?,?>) {
                                Map<?,?> roleMap = (Map<?,?>) role;
                                Object valor = roleMap.get("role");
                                return valor != null ? valor.toString() : "";
                            } else {
                                return role != null ? role.toString() : "";
                            }
                        })
                        .collect(Collectors.joining(","));
            }


            Object permissionsObj = claims.get("permissions");
            String permissionsHeader = "";
            if (permissionsObj instanceof List<?>) {
                List<?> permissionsList = (List<?>) permissionsObj;
                permissionsHeader = permissionsList.stream()
                        .map(perm -> {
                            if (perm instanceof String) {
                                return (String) perm;
                            } else if (perm instanceof Map<?,?>) {
                                Map<?,?> permMap = (Map<?,?>) perm;
                                Object valor = permMap.get("permission");
                                return valor != null ? valor.toString() : "";
                            } else {
                                return perm != null ? perm.toString() : "";
                            }
                        })
                        .collect(Collectors.joining(","));
            }



            // Agregar la información extra a los headers para que los microservicios la reciban
            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                    .header("X-Username", username != null ? username : "")
                    .header("X-User-Id", userId != null ? userId : "")
                    .header("X-Profile-Id", profileId != null ? profileId : "")
                    .header("X-Roles", rolesHeader)
                    .header("X-Permissions", permissionsHeader)
                    .build();

            ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();

            return chain.filter(mutatedExchange);

        }

        return chain.filter(exchange);
    }

}
