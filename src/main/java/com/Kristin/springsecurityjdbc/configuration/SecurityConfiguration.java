package com.Kristin.springsecurityjdbc.configuration;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
	
	@Autowired
	DataSource datasource;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication()
			.dataSource(datasource)
			.usersByUsernameQuery("select username, password, enabled " 
					+ "from users " 
					+ "where username = ?")
			.authoritiesByUsernameQuery("select username, authority " + 
					"from authorities " + 
					"where username = ?");
			
		//This below creates a database schema with hard coded user/password which should
		//be done in production
//			.withDefaultSchema() //uses spring security to create the roles and such tables
//			.withUser(
//					User.withUsername("user")
//					.password("pass")
//					.roles("USER")
//					)
//			.withUser(
//					User.withUsername("admin")
//					.password("pass")
//					.roles("ADMIN")
//					);
			
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
			.antMatchers("/admin").hasRole("ADMIN")
			.antMatchers("/user").hasAnyRole("ADMIN", "USER")
			.antMatchers("/").permitAll()
			.and().formLogin();
	}
	
	@Bean
	public PasswordEncoder getPasswordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
	
	
	

}
