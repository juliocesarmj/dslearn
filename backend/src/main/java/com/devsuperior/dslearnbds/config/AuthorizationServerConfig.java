package com.devsuperior.dslearnbds.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import com.devsuperior.dslearnbds.components.JwtTokenEnhancer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
	
	@Value("${security.oauth2.client.client-id}")
	private String clientId;
	
	@Value("${security.oauth2.client.client-secret}")
	private String clientSecret;
	
	@Value("${jwt.duration}")
	private Integer jwtDuration;
	
	private BCryptPasswordEncoder passwordEncoder;
	private JwtAccessTokenConverter accessTokenConverter;
	private JwtTokenStore tokenStore;
	private AuthenticationManager authenticationManager;
	private JwtTokenEnhancer tokenEnhancer;
	private UserDetailsService userDetailsService;
	
	@Autowired
	public AuthorizationServerConfig(BCryptPasswordEncoder passwordEncoder,
			JwtAccessTokenConverter accessTokenConverter,
			JwtTokenStore tokenStore,
			AuthenticationManager authenticationManager,
			JwtTokenEnhancer tokenEnhancer,
			UserDetailsService userDetailsService) {
		this.passwordEncoder = passwordEncoder;
		this.accessTokenConverter = accessTokenConverter;
		this.tokenStore = tokenStore;
		this.authenticationManager = authenticationManager;
		this.tokenEnhancer = tokenEnhancer;
		this.userDetailsService = userDetailsService;
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.tokenKeyAccess("permiteAll()").checkTokenAccess("isAuthenticated()");
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory()
		.withClient(this.clientId)
		.secret(this.passwordEncoder.encode(this.clientSecret))
		.scopes("read", "write")
		.authorizedGrantTypes("password", "refresh_token")
		.accessTokenValiditySeconds(this.jwtDuration)
		.refreshTokenValiditySeconds(this.jwtDuration);
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		
		TokenEnhancerChain chain = new TokenEnhancerChain();
		chain.setTokenEnhancers(Arrays.asList(this.accessTokenConverter, this.tokenEnhancer));
		
		endpoints.authenticationManager(this.authenticationManager)
		.tokenStore(this.tokenStore)
		.accessTokenConverter(this.accessTokenConverter)
		.tokenEnhancer(chain)
		.userDetailsService(this.userDetailsService);
	}
}
