package com.chetan.app.ws.security;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.chetan.app.ws.service.UserService;

@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

	private final UserService userDetailsService;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	public WebSecurity(UserService userDetailsService, BCryptPasswordEncoder bCryptPasswordEncoder) {
		this.userDetailsService = userDetailsService;

		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
	}

	/*Basically the below override method helps in 
	 * making any endpoint public, as enabling spring security makes
	 * all the endpoints secure.*/
	@Override
	protected void configure(HttpSecurity http) throws Exception
	{
		http
		.csrf()
		.disable()
		.authorizeRequests()
		.antMatchers(HttpMethod.POST, SecurityConstants.SIGN_UP_URL) // allows POST to be public
		.permitAll() //permits all request
		.anyRequest() //any other type of HttpMethod
		.authenticated()//auth is required
		.and()
		//.addFilter(new AuthenticationFilter(authenticationManager())); //If default /login binding is needed
		.addFilter(getAuthenticationFilter()) //for custom url login binding
		.addFilter(new AuthorizationFilter(authenticationManager()))//for auth of protected end points
		.sessionManagement() //to make the spring not use http session, as http session will cache inof including
		                     //header which we don't want
		.sessionCreationPolicy(SessionCreationPolicy.STATELESS); //seeting the session to be stateless
	}
	
	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception
	{
		auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
	}
	
	/*By deafuly spring provides /login binding to the app
	 * however if custome url is needed then below method is the way*/
	
	public AuthenticationFilter getAuthenticationFilter() throws Exception
	{
		final AuthenticationFilter filter = new AuthenticationFilter(authenticationManager());
		filter.setFilterProcessesUrl("/users/login");
		return filter;
	}
	
}
