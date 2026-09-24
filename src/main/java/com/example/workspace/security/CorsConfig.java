package com.example.workspace.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class CorsConfig {

    /*
     * @Configuration tells Spring:
     *
     * "This class contains configuration that Spring should process
     * and use to create/register beans in the ApplicationContext."
     *
     * So Spring will inspect the @Bean methods below and potentially
     * add their returned objects to the ApplicationContext.
     */


    /*
     * LOCAL CORS CONFIGURATION
     *
     * This bean exists only when the "local" Spring profile is active.
     *
     * Example:
     *
     * spring.profiles.active=local
     *
     * Then Spring creates this CorsConfigurationSource bean.
     *
     * If the active profile is "prod", this method is ignored and
     * this bean is NOT created.
     */
    @Bean("corsConfigurationSource")
    @Profile("local")
    public CorsConfigurationSource corsConfigurationSource() {

        /*
         * The frontend can run on different localhost ports.
         *
         * React CRA:
         * http://localhost:3000
         *
         * Vite:
         * http://localhost:5173
         *
         * These are different origins because the port is part
         * of an origin.
         */
        return buildSource(
                List.of(
                        "http://localhost:3000",
                        "http://localhost:5173"
                )
        );
    }


    /*
     * PRODUCTION CORS CONFIGURATION
     *
     * This bean exists only when the "prod" profile is active.
     *
     * In production, we should allow only our actual deployed
     * frontend origin.
     */
    @Bean("corsConfigurationSource")
    @Profile("prod")
    public CorsConfigurationSource prodCorsConfigurationSource() {

        return buildSource(
                List.of("https://your-frontend.prod.app")
        );
    }


    /*
     * This method builds the actual CORS configuration.
     *
     * We return CorsConfigurationSource rather than directly
     * returning CorsConfiguration because Spring needs a way to
     * determine:
     *
     *     "For this incoming request URL, which CORS configuration
     *      should I use?"
     *
     * UrlBasedCorsConfigurationSource provides that URL-based lookup.
     */
    private CorsConfigurationSource buildSource(List<String> allowedOrigins) {

        /*
         * CorsConfiguration represents the RULES for CORS.
         *
         * Think of this object as:
         *
         *     "What cross-origin requests am I willing to allow?"
         */
        CorsConfiguration config = new CorsConfiguration();


        /*
         * ALLOWED ORIGINS
         *
         * An origin consists of:
         *
         *     scheme + host + port
         *
         * Example:
         *
         *     http://localhost:3000
         *     └──┬──┘ └──────┬──────┘
         *      scheme       host:port
         *
         * The browser sends the frontend's origin in the request:
         *
         *     Origin: http://localhost:3000
         *
         * Spring checks whether that origin is present in this list.
         *
         * If it is:
         *
         *     CORS request can be allowed
         *
         * If it isn't:
         *
         *     CORS request is rejected
         */
        config.setAllowedOrigins(allowedOrigins);


        /*
         * ALLOWED HTTP METHODS
         *
         * CORS is not only about the origin.
         *
         * We also specify which HTTP methods can be used
         * for cross-origin requests.
         *
         * Example:
         *
         *     GET       -> fetch data
         *     POST      -> create/login/register
         *     PUT       -> replace/update
         *     PATCH     -> partial update
         *     DELETE    -> delete
         *     OPTIONS   -> browser's CORS preflight request
         *
         * OPTIONS is especially important.
         *
         * The browser may first send:
         *
         *     OPTIONS /api/notes
         *
         * to ask the server:
         *
         *     "Am I allowed to make the actual request?"
         */
        config.setAllowedMethods(
                List.of(
                        "GET",
                        "POST",
                        "PUT",
                        "PATCH",
                        "DELETE",
                        "OPTIONS"
                )
        );


        /*
         * ALLOWED REQUEST HEADERS
         *
         * These are headers that the browser is allowed to send
         * in the cross-origin request.
         *
         * Authorization is important for our application because
         * the frontend will send something like:
         *
         *     Authorization: Bearer <JWT>
         *
         * Content-Type is needed for requests such as:
         *
         *     Content-Type: application/json
         *
         * Since Authorization is not one of the browser's simple
         * CORS-safe request headers, it needs to be explicitly
         * allowed here.
         */
        config.setAllowedHeaders(
                List.of(
                        "Authorization",
                        "Content-Type"
                )
        );


        /*
         * ALLOW CREDENTIALS
         *
         * "Credentials" here mainly refers to browser-managed
         * credentials such as cookies.
         *
         * Our authentication design uses:
         *
         *     Authorization: Bearer <JWT>
         *
         * rather than authentication cookies.
         *
         * Therefore, we don't need:
         *
         *     Access-Control-Allow-Credentials: true
         *
         * So this remains false.
         */
        config.setAllowCredentials(false);


        /*
         * NOW WE CREATE THE CORS CONFIGURATION SOURCE
         *
         * CorsConfiguration describes the rules.
         *
         * CorsConfigurationSource answers:
         *
         *     "Which rules should be used for this request?"
         *
         * UrlBasedCorsConfigurationSource is an implementation
         * that lets us associate CORS configurations with URL
         * patterns.
         */
        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();


        /*
         * THIS IS THE IMPORTANT LINE:
         *
         *     source.registerCorsConfiguration("/api/**", config);
         *
         * It means:
         *
         *     "Whenever a request matches /api/**,
         *      use this CorsConfiguration."
         *
         *
         * "/api/**" means:
         *
         *     /api/health
         *     /api/auth/login
         *     /api/auth/register
         *     /api/notes
         *     /api/notes/123
         *     /api/users/profile
         *
         * etc.
         *
         * All of those URLs use the CORS rules stored in "config".
         *
         *
         * You can think of it like a map:
         *
         *     URL pattern       -> CORS rules
         *     --------------------------------
         *     /api/**           -> config
         *
         *
         * Why do we need this?
         *
         * Because CorsConfigurationSource is not itself the rules.
         *
         * It is the SOURCE Spring asks:
         *
         *     "Give me the CORS configuration for this request."
         *
         * The source looks at the request path and finds the
         * configuration registered for that path.
         */
        source.registerCorsConfiguration("/api/**", config);

        return source;
    }
}