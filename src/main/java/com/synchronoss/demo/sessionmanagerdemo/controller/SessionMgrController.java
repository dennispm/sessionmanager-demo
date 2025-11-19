package com.synchronoss.demo.sessionmanagerdemo.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class SessionMgrController {

    public static final String PWA_REDIRECT_URL_COOKIE="PWA_REDIRECT_URL";

    @Value( "${demo.dxp-login-url}" )
    private String dxpLoginUrl;

    @Value( "${demo.sm-callbak-url}" )
    private String smCallbackUrl;

    @Value( "${demo.cors-origin-url}" )
    private String corsOriginUrl;

    @RequestMapping("/")
    public String index() {
        return "Greetings from Spring Boot!v- SessionManager Demo";
    }

    //check for cookie for access token
    //if cookie not present respond with status 401, dxp login url and sm callback url
    @PostMapping("/auth")
    public ResponseEntity readCookie(HttpServletRequest request,
                                     HttpServletResponse response,
                                     @CookieValue(value = "SESSION_COOKIE", defaultValue = "") String sessionCookie,
                                     @RequestParam(defaultValue="") String pwaRedirectUrl) {
        System.out.println("processing auth request. pwa refdirect url: "+pwaRedirectUrl);

        System.out.println("dxpLoginUrl "+dxpLoginUrl);
        System.out.println("smCallbackUrl"+smCallbackUrl);
        System.out.println("corsOriginUrl"+corsOriginUrl);

        Cookie[] cookies = request.getCookies();
        String bodyString = getCookies(request);
        System.out.println("cookies from client: "+bodyString);

        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add("Access-Control-Allow-Origin", corsOriginUrl);

        responseHeaders.add("Access-Control-Allow-Methods","GET, POST, OPTIONS");
        responseHeaders.add("Access-Control-Allow-Headers",
                "Location, Origin, Content-Type, Accept, Authorization, X-Request-With, Set-Cookie, Cookie, Bearer");
        responseHeaders.add("Access-Control-Allow-Credentials","true");
        //same action if acess&refresh tokens expired or cookie not present
        if (sessionCookie.isEmpty()) {
            System.out.println("sessionCookie is not present");
            //save pwa redirect url in cookie
            Cookie cookie = new Cookie(PWA_REDIRECT_URL_COOKIE, pwaRedirectUrl);
            response.addCookie(cookie);
            String loginRedirectUrl = dxpLoginUrl+"?callbackUrl="+smCallbackUrl;
            responseHeaders.add(HttpHeaders.LOCATION, loginRedirectUrl);
            return new ResponseEntity<String>(loginRedirectUrl, responseHeaders, HttpStatus.UNAUTHORIZED);
        }
        //create ATP tokens and add to cookie
        String cloudToken="refreshtoken:accesstoken";
        Cookie tokenCookie = new Cookie("TOKEN_COOKIE", cloudToken);
        response.addCookie(tokenCookie);

        return new ResponseEntity<String>(responseHeaders, HttpStatus.OK);
    }

    //session manager callback end point for auth provider(dxp for example) to call back after successful login
    //creates access and refresh tokens and save then in cookie
    //redirect the browser to pwa call back url privided before
    @GetMapping("/smCallBack")
    public ResponseEntity smCallBack(@RequestParam(defaultValue="") String providerToken, HttpServletResponse response, @CookieValue(value = PWA_REDIRECT_URL_COOKIE, defaultValue = "")String pwaCallbackUrl) {
        System.out.println("processing smCallBack. pwaCallbackUrl: "+pwaCallbackUrl);

        // create a cookie
        // validate authenticity of callback
        Cookie jwtTokenCookie = new Cookie("SESSION_COOKIE", "c2FtLnNtaXRoQGV4YW1wbGUuY29t");

        jwtTokenCookie.setMaxAge(86400);
        jwtTokenCookie.setHttpOnly(true);
        response.addCookie(jwtTokenCookie);
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add("Access-Control-Allow-Origin", corsOriginUrl);
        //create ATP tokens and add to cookie
        String cloudToken="refreshtoken:accesstoken";
        Cookie tokenCookie = new Cookie("TOKEN_COOKIE", cloudToken);
        response.addCookie(tokenCookie);

        responseHeaders.add("Access-Control-Allow-Methods","GET, POST, OPTIONS");
        responseHeaders.add("Access-Control-Allow-Headers","Origin, Content-Type, Accept, Authorization, X-Request-With, Set-Cookie, Cookie, Bearer");
        responseHeaders.add("Access-Control-Allow-Credentials","true");
        responseHeaders.add(HttpHeaders.LOCATION, pwaCallbackUrl);
        responseHeaders.add("X-CSRF-TOKEN", "test-csrf-token");
        return new ResponseEntity<String>(responseHeaders, HttpStatus.FOUND);
    }

    //clear the cookies for logout
    @GetMapping("/clear-session|asdfg")
    public ResponseEntity resetSessionCookie(HttpServletResponse response) {
        System.out.println("processing clear-session");
        // create a cookie
        Cookie cookie = new Cookie("SESSION_COOKIE", "");

        //add cookie to response
        response.addCookie(cookie);
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add("Access-Control-Allow-Origin", corsOriginUrl);

        responseHeaders.add("Access-Control-Allow-Methods","GET, POST, OPTIONS");
        responseHeaders.add("Access-Control-Allow-Headers","Origin, Content-Type, Accept, Authorization, X-Request-With, Set-Cookie, Cookie, Bearer");
        responseHeaders.add("Access-Control-Allow-Credentials","true");

        return new ResponseEntity<String>("session cookie reset", responseHeaders, HttpStatus.OK);
    }
    @GetMapping("/{name:[a-z-]+\\d\\.|asasdas}")
    public ResponseEntity readAllCookiesGet1(HttpServletRequest request) {
        System.out.println("processing all-cookies readAllCookiesGet1");
        String bodyString = getCookies(request);
        System.out.println("cookies: "+bodyString);
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add("Access-Control-Allow-Origin", corsOriginUrl);

        responseHeaders.add("Access-Control-Allow-Methods","GET, POST, OPTIONS");
        responseHeaders.add("Access-Control-Allow-Headers","Origin, Content-Type, Accept, Authorization, X-Request-With, Set-Cookie, Cookie, Bearer");
        responseHeaders.add("Access-Control-Allow-Credentials","true");
        return new ResponseEntity<String>(bodyString, responseHeaders, HttpStatus.OK);
    }

    @GetMapping("/all-cookies")
    public ResponseEntity readAllCookiesGet(HttpServletRequest request) {
        System.out.println("processing all-cookies");
        String bodyString = getCookies(request);
        System.out.println("cookies: "+bodyString);
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add("Access-Control-Allow-Origin", corsOriginUrl);

        responseHeaders.add("Access-Control-Allow-Methods","GET, POST, OPTIONS");
        responseHeaders.add("Access-Control-Allow-Headers","Origin, Content-Type, Accept, Authorization, X-Request-With, Set-Cookie, Cookie, Bearer");
        responseHeaders.add("Access-Control-Allow-Credentials","true");
        return new ResponseEntity<String>(bodyString, responseHeaders, HttpStatus.OK);
    }

    @GetMapping("/auth-get")
    public ResponseEntity readCookieGet(HttpServletRequest request, @CookieValue(value = "SESSION_COOKIE", defaultValue = "") String sessionCookie) {
        System.out.println("processing auth request");
        Cookie[] cookies = request.getCookies();
        String bodyString = "no cookies";
        if (cookies != null) {
            bodyString =  Arrays.stream(cookies)
                    .map(c -> c.getName() + "=" + c.getValue()).collect(Collectors.joining(", "));
        }
        System.out.println("cookies from client: "+bodyString);
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add("Access-Control-Allow-Origin", corsOriginUrl);

        responseHeaders.add("Access-Control-Allow-Methods","GET, POST, OPTIONS");
        responseHeaders.add("Access-Control-Allow-Headers","Location, Origin, Content-Type, Accept, Authorization, X-Request-With, Set-Cookie, Cookie, Bearer");
        responseHeaders.add("Access-Control-Allow-Credentials","true");

        if (sessionCookie.isEmpty()) {
            System.out.println("sessionCookie is not present");

            responseHeaders.add(HttpHeaders.LOCATION, dxpLoginUrl);
            return new ResponseEntity<String>("UNAUTHORIZED,"+dxpLoginUrl+","+smCallbackUrl, responseHeaders, HttpStatus.OK);
        }

        return new ResponseEntity<String>("Welcome!", responseHeaders, HttpStatus.OK);
    }
    void addCookie(String name, String value, HttpServletResponse response){
        Cookie cookie = new Cookie(name, value);
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);
    }
    void deleteCookie(String name, HttpServletResponse response){
        Cookie cookie = new Cookie(name, null);
        cookie.setMaxAge(0);
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);
    }

    @GetMapping("/clearcookies")
    public ResponseEntity resetCookies(HttpServletRequest request, HttpServletResponse response) {
        System.out.println("processing clearcookies");
        // create a cookie
        Cookie[] cookies = request.getCookies();
        String bodyString = "no cookies";
        if (cookies != null) {
            bodyString =  Arrays.stream(cookies)
                    .map(c -> c.getName() + "=" + c.getValue()).collect(Collectors.joining(", "));
        }
        System.out.println("cookies: "+bodyString);
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add("Access-Control-Allow-Origin", corsOriginUrl);

        responseHeaders.add("Access-Control-Allow-Methods","GET, POST, OPTIONS");
        responseHeaders.add("Access-Control-Allow-Headers","Location, Origin, Content-Type, Accept, Authorization, X-Request-With, Set-Cookie, Cookie, Bearer");
        responseHeaders.add("Access-Control-Allow-Credentials","true");

        if(cookies != null){
            for(Cookie cookie : cookies){
                cookie.setValue(null);
                cookie.setMaxAge(0);
                response.addCookie(cookie);
            }
        }

        return new ResponseEntity<String>("session cookie reset", responseHeaders, HttpStatus.OK);
    }

    private String getCookies(HttpServletRequest request){
        Cookie[] cookies = request.getCookies();
        String bodyString = "no cookies";
        if (cookies != null) {
            bodyString =  Arrays.stream(cookies)
                    .map(c -> c.getName() + "=" + c.getValue()).collect(Collectors.joining(", "));
        }
        return bodyString;
    }
}
