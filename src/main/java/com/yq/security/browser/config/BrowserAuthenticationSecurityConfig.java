package com.yq.security.browser.config;

import com.yq.security.core.authentication.AbstractChannelSecurityConfig;
import com.yq.security.core.authentication.mobile.SmsCodeAuthenticationSecurityConfig;
import com.yq.security.core.authentication.restful.RestAuthenticationEntryPoint;
import com.yq.security.core.authentication.restful.RestAuthenticationFilter;
import com.yq.security.core.authentication.restful.RestAuthenticationProvider;
import com.yq.security.core.authentication.restful.RestAuthenticationSecurityConfig;
import com.yq.security.core.authentication.restful.encoder.MD5Encoder;
import com.yq.security.core.authentication.restful.handler.RestAuthenticationFailureHandler;
import com.yq.security.core.authentication.restful.handler.RestAuthenticationSuccessHandler;
import com.yq.security.core.properties.SecurityConstants;
import com.yq.security.core.properties.SecurityProperties;
import com.yq.security.core.validate.ValidateCodeSecurityConfig;
import com.yq.security.core.validate.ValidateConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;

/**
 * @Auther: yq
 * @Date: 2018-11-02 14:29
 * @Description:
 */
@Configuration
@EnableWebSecurity
public class BrowserAuthenticationSecurityConfig  extends AbstractChannelSecurityConfig {

    @Autowired
    private SecurityProperties securityProperties;

    @Autowired
    private RememberMeServices rememberMeServices;

    @Autowired
    private SmsCodeAuthenticationSecurityConfig smsCodeAuthenticationSecurityConfig;

    @Autowired
    private RestAuthenticationSecurityConfig restAuthenticationSecurityConfig;

    @Autowired
    private ValidateCodeSecurityConfig validateCodeSecurityConfig;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        applyPasswordAuthenticationConfig(http);
        http
                .csrf().disable()
                .apply(smsCodeAuthenticationSecurityConfig)
                    .and()
                .apply(restAuthenticationSecurityConfig)
                    .and()
                .apply(validateCodeSecurityConfig)
                    .and()
                .exceptionHandling().authenticationEntryPoint(new RestAuthenticationEntryPoint())
                .and()
                .authorizeRequests()
                .antMatchers(SecurityConstants.DEFAULT_LOGIN_PAGE_URL.value()).permitAll()
                .antMatchers(SecurityConstants.DEFAULT_UNAUTHENTICATION_URL_JSON.value()).permitAll()
                .antMatchers(SecurityConstants.DEFAULT_LOGOUT_PROCESSING_URL_FORM.value()).permitAll()
                .antMatchers(SecurityConstants.DEFAULT_LOGIN_PROCESSING_APP_URL_FORM.value()).permitAll()
                .antMatchers(SecurityConstants.DEFAULT_LOGIN_PROCESSING_BROWSER_URL_FORM.value()).permitAll()
                .antMatchers(SecurityConstants.DEFAULT_CHECK_USER.value()).permitAll()
                .antMatchers(SecurityConstants.DEFAULT_HOME.value()).permitAll()
                .antMatchers("/favicon.ico").permitAll()
                .antMatchers(SecurityConstants.DEFAULT_VALIDATE_CODE_URL_PREFIX.value()).permitAll()
                .antMatchers(ValidateConstants.DEFAULT_VALIDATE_CODE_URL_PREFIX + "/**").permitAll()
                .anyRequest().authenticated()
                .and()
                //开启cookie储存用户信息，并设置有效期为14天，指定cookie中的密钥
                .rememberMe()
                .tokenValiditySeconds(securityProperties.getRememberMe().getTokenValiditySeconds())
                .rememberMeServices(rememberMeServices)
                .key(securityProperties.getRememberMe().getKey());

    }



}
