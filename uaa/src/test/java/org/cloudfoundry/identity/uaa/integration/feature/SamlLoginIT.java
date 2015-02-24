/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.integration.feature;

import java.util.Map;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import org.cloudfoundry.identity.uaa.login.test.LoginServerClassRunner;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.web.client.RestOperations;

@RunWith(LoginServerClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class SamlLoginIT {

    @Autowired @Rule
    public IntegrationTestRule integrationTestRule;

    @Autowired
    RestOperations restOperations;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Autowired
    TestAccounts testAccounts;

    @Test
    public void testSamlVariations() throws Exception {
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(baseUrl + "/login");
        Assert.assertEquals("Cloud Foundry", webDriver.getTitle());

        webDriver.findElement(By.name("username"));
        webDriver.findElement(By.name("password"));
        webDriver.findElement(By.xpath("//a[text()='Okta Preview 1']"));
        webDriver.findElement(By.xpath("//a[text()='Okta Preview 2']"));
        webDriver.findElement(By.xpath("//a[text()='Log in with OpenAM']"));
        webDriver.findElement(By.xpath("//a[text()='Log in with vCenter SSO']"));
        webDriver.findElement(By.xpath("//a[text()='Log in with Simple SAML PHP']"));
        webDriver.findElement(By.xpath("//input[@value='Sign in']"));
        Assert.assertEquals(3, webDriver.findElements(By.xpath("//input")).size());
    }

    @Test
    public void testContentTypes() throws Exception {
        webDriver.get(baseUrl + "/logout.do");
        String loginUrl = baseUrl + "/login";

        HttpHeaders jsonHeaders = new HttpHeaders();
        jsonHeaders.add("Accept", "application/json");
        ResponseEntity<Map> jsonResponseEntity = restOperations.exchange(loginUrl,
            HttpMethod.GET,
            new HttpEntity<>(jsonHeaders),
            Map.class);
        assertThat(jsonResponseEntity.getHeaders().get("Content-Type").get(0), containsString(APPLICATION_JSON_VALUE));

        HttpHeaders htmlHeaders = new HttpHeaders();
        htmlHeaders.add("Accept", "text/html");
        ResponseEntity<Void> htmlResponseEntity = restOperations.exchange(loginUrl,
            HttpMethod.GET,
            new HttpEntity<>(htmlHeaders),
            Void.class);
        assertThat(htmlResponseEntity.getHeaders().get("Content-Type").get(0), containsString(TEXT_HTML_VALUE));

        HttpHeaders defaultHeaders = new HttpHeaders();
        defaultHeaders.add("Accept", "*/*");
        ResponseEntity<Void> defaultResponseEntity = restOperations.exchange(loginUrl,
            HttpMethod.GET,
            new HttpEntity<>(defaultHeaders),
            Void.class);
        assertThat(defaultResponseEntity.getHeaders().get("Content-Type").get(0), containsString(TEXT_HTML_VALUE));
    }

    @Test
    public void testSimpleSamlPhpLogin() {
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(baseUrl + "/login");
        Assert.assertEquals("Cloud Foundry", webDriver.getTitle());
        webDriver.findElement(By.xpath("//a[text()='Log in with Simple SAML PHP']")).click();
        webDriver.findElement(By.xpath("//h2[contains(text(), 'Enter your username and password')]"));
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Login']")).click();
        assertThat(webDriver.findElement(By.cssSelector("h1")).getText(), Matchers.containsString("Where to?"));

    }
}
