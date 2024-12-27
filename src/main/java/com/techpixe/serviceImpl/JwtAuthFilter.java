package com.techpixe.serviceImpl;



import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthFilter extends OncePerRequestFilter 
{

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private BlackList blackList;  // Inject BlackList service

//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)throws ServletException, IOException         
//    {
//
//        String authHeader = request.getHeader("Authorization");
//        
//        //authHeader contains Bearer and Token.
//
//        // Check if token is present and starts with 'Bearer '
//        if (authHeader != null && authHeader.startsWith("Bearer "))
//        {
//            String token = authHeader.substring(7);  // Remove "Bearer " prefix
//
//            // Check if the token is blacklisted
//            if (blackList.isBlackListed(token))
//            {
//            	System.err.println("**Token is blacklisted**");
//            	
//            	throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Token is blacklisted");
//            }
//
//            // Validate the token
//            if (jwtUtils.isTokenValid(token))
//            {
//                String email = jwtUtils.extractEmail(token);  // Extract email
//                UserDetails userDetails = userDetailsService.loadUserByUsername(email);
//
//                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
//                        userDetails, null, userDetails.getAuthorities());
//
//                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                SecurityContextHolder.getContext().setAuthentication(authToken);
//            }
//        }
//
//        // Continue the filter chain
//        chain.doFilter(request, response);
//    }
    
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)throws ServletException, IOException
    {
        String authHeader = request.getHeader("Authorization");
        
        // Check if token is present and starts with 'Bearer '
        if (authHeader != null && authHeader.startsWith("Bearer "))
        {
            String token = authHeader.substring(7);

            try 
            {
                // Check if token is blacklisted
                if (blackList.isBlackListed(token))
                {
                    throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token is blacklisted");
                }

                // Validate the token
                if (jwtUtils.isTokenValid(token))
                {
                    String email = jwtUtils.extractEmail(token);
                    UserDetails userDetails = userDetailsService.loadUserByUsername(email);

                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());

                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            } 
            catch (ResponseStatusException ex) 
            {
                // Handle custom exception for token expiration or blacklist
                response.setStatus(ex.getStatusCode().value());
                response.getWriter().write("{\"error\":\"" + ex.getReason() + "\"}");
                response.setContentType("application/json");
                return; // Skip further filter processing
            }
        }

        chain.doFilter(request, response);
    }

    
    
       
}


