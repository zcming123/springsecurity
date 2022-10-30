package com.lagou.config;

import com.lagou.domain.Permission;
import com.lagou.filter.ValidateCodeFilter;
import com.lagou.handle.MyAccessDeniedHandler;
import com.lagou.service.PermissionService;
import com.lagou.service.impl.MyAuthenticationService;
import com.lagou.service.impl.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.sql.DataSource;
import java.util.List;

/**
 * spring security 配置类
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)//开启注解支持
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    MyUserDetailsService myUserDetailsService;

    @Autowired
    MyAuthenticationService myAuthenticationService;


    /**
     * 身份安全管理器
     *
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(myUserDetailsService);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 解决静态资源被拦截的问题
        web.ignoring().antMatchers("/css/**", "/images/**", "/js/**", "/code/**");
    }

    @Autowired
    ValidateCodeFilter validateCodeFilter;

    @Autowired
    MyAccessDeniedHandler myAccessDeniedHandler;

    @Autowired
    PermissionService permissionService;

    /**
     * http请求方法
     *
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /*http.httpBasic() // 开启httpbasic认证
                .and().authorizeRequests().anyRequest().authenticated();//所有请求都需要认证之后才能访问*/

//        http.formLogin() // 开启表单认证，默认就是表单认证方式
//                .and().authorizeRequests().anyRequest().authenticated();

        // 加入用户名密码验证过滤器的前面
        http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class);

        // 设置/user开头的请求需要ADMIN权限  Role角色 和 Authority权限 都是严格区分大小写的。
        // http.authorizeRequests().antMatchers("/user/**").hasRole("ADMIN");
        // 设置/product 开头的请求需要ADMIN 或者 PRODUCT权限 并且访问的IP是127.0.0.1
        /*http.authorizeRequests().antMatchers("/product/**").access
                ("hasAnyRole('ADMIN','PRODUCT') and hasIpAddress('127.0.0.1')");*/

        // 使用自定义bean完成授权
        /*http.authorizeRequests().antMatchers("/user/{id}")
                .access("@myAuthorizationService.check(authentication,request,#id)");*/

        // 查询数据库所有权限列表
        List<Permission> list = permissionService.list();
        for (Permission permission : list) {
            // 添加请求权限
            http.authorizeRequests().antMatchers(permission.getPermissionUrl())
                    .hasAuthority(permission.getPermissionTag());
        }

        // 设置权限不足的信息
        http.exceptionHandling().accessDeniedHandler(myAccessDeniedHandler);

        http.formLogin()// 开启表单认证
                .loginPage("/toLoginPage")// 自定义登录页面
                .loginProcessingUrl("/login")//表单提交的路径
                .usernameParameter("username")
                .passwordParameter("password")//自定义input的name值
                .successForwardUrl("/")//登录成功之后跳转的路径
                .successHandler(myAuthenticationService)
                .failureHandler(myAuthenticationService)//登录成功或者失败后的处理
                .and().logout().logoutUrl("/logout")
                // .logoutSuccessUrl 与 .logoutSuccessHandler 是相互冲突的。
                // 如果指定了 .logoutSuccessHandler ，.logoutSuccessUrl 会被忽略。还是得过一遍官方API文档啊。
//                .logoutSuccessUrl("/toLoginPage")
                // 这里有一个坑：如果开启了 CSRF防护，则需要以 post请求来访问 /logout
                // 或者 加上这句 .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))  我懒得改前端了
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
//                .logoutSuccessHandler(myAuthenticationService)
                .and().rememberMe()//开启记住我功能
                .tokenValiditySeconds(1209600)//token失效时间 默认是2周
                .rememberMeParameter("remember-me")//自定义表单input值
                .tokenRepository(getPersistentTokenRepository())
                .and().authorizeRequests().antMatchers("/toLoginPage").permitAll()//放行登录页面
                .anyRequest().authenticated();
        //关闭csrf防护
        //http.csrf().disable();
        //默认开启csrf防护. 定义哪些路径不需要防护
        //http.csrf().ignoringAntMatchers("/user/saveOrUpdate");

        //加载同源域名下iframe页面
        http.headers().frameOptions().sameOrigin();

        // session 管理这块还有点问题：无法跳转链接。
//        http.sessionManagement()// 设置session管理
//            .invalidSessionUrl("/toLoginPage2")// session失效之后跳转的路径，默认是登录页面。失效但未过期，not expired but entirely invalid
//            .maximumSessions(1)// session最大会话数量 1,同一时间只能有一个用户可以登录  互踢
//            .maxSessionsPreventsLogin(true)//如果达到最大会话数量,就阻止登录。阻止登录后，.expiredUrl 的效果就无法显示了。
//            .expiredUrl("/toLoginPage1");// session过期之后跳转的路径。超时、过期的

        // 开启跨域支持
        http.cors().configurationSource(corsConfigurationSource());
    }

    @Autowired
    DataSource dataSource;

    /**
     * 负责token与数据库之间的操作
     *
     * @return
     */
    @Bean
    public PersistentTokenRepository getPersistentTokenRepository() {
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);//设置数据源
        // tokenRepository.setCreateTableOnStartup(true);//启动时帮助我们自动创建一张表, 第一次启动设置true 第二次启动设置false或者注释
        return tokenRepository;
    }

    /**
     * 跨域配置信息源
     */
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        //允许跨域的站点
        corsConfiguration.addAllowedOrigin("*");
        //允许跨域的http方法
        corsConfiguration.addAllowedMethod("*");
        // 允许跨域的请求头
        corsConfiguration.addAllowedHeader("*");
        // 允许带凭证
        corsConfiguration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();
        // 对所有url都生效
        urlBasedCorsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);

        return urlBasedCorsConfigurationSource;
    }
}
