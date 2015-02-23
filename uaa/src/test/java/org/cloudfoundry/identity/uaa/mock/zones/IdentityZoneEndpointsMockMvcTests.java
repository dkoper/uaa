package org.cloudfoundry.identity.uaa.mock.zones;

import com.googlecode.flyway.core.Flyway;
import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneCreationRequest;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.event.IdentityZoneModifiedEvent;
import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class IdentityZoneEndpointsMockMvcTests extends TestClassNullifier {
    private static XmlWebApplicationContext webApplicationContext;
    private static MockMvc mockMvc;
    private static String identityClientToken = null;
    private static String adminToken = null;
    private static TestClient testClient = null;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private static TestApplicationEventListener<IdentityZoneModifiedEvent> eventListener;

    @BeforeClass
    public static void setUp() throws Exception {
        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setServletContext(new MockServletContext());
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "uaa.yml,login.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.refresh();
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);

        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).addFilter(springSecurityFilterChain)
            .build();
        testClient = new TestClient(mockMvc);

        eventListener = TestApplicationEventListener.forEventClass(IdentityZoneModifiedEvent.class);
        webApplicationContext.addApplicationListener(eventListener);

        identityClientToken = testClient.getClientCredentialsOAuthAccessToken(
                "identity",
                "identitysecret",
                "zones.create");
        adminToken = testClient.getClientCredentialsOAuthAccessToken(
            "admin",
            "adminsecret",
            "");
    }

    @AfterClass
    public static void tearDown() throws Exception {
        Flyway flyway = webApplicationContext.getBean(Flyway.class);
        flyway.clean();
        webApplicationContext.close();
    }

    @Before
    public void before() {
        IdentityZoneHolder.clear();
        eventListener.clearEvents();
    }

    @After
    public void after() {
        IdentityZoneHolder.clear();
    }

    private ScimUser createUser(String token, String subdomain) throws Exception {
        ScimUser user = getScimUser();

        byte[] requestBody = new ObjectMapper().writeValueAsBytes(user);
        MockHttpServletRequestBuilder post = post("/Users")
                .header("Authorization", "Bearer " + token)
                .contentType(APPLICATION_JSON)
                .content(requestBody);
        if (subdomain != null && !subdomain.equals("")) post.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));

        MvcResult result = mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andExpect(header().string("ETag", "\"0\""))
                .andExpect(jsonPath("$.userName").value(user.getUserName()))
                .andExpect(jsonPath("$.emails[0].value").value(user.getUserName()))
                .andExpect(jsonPath("$.name.familyName").value(user.getFamilyName()))
                .andExpect(jsonPath("$.name.givenName").value(user.getGivenName()))
                .andReturn();

        return new ObjectMapper().readValue(result.getResponse().getContentAsString(), ScimUser.class);
    }

    private ScimUser getScimUser() {
        String email = "joe@"+generator.generate().toLowerCase()+".com";
        ScimUser user = new ScimUser();
        user.setUserName(email);
        user.setName(new ScimUser.Name("Joe", "User"));
        user.addEmail(email);
        return user;
    }

    @Test
    public void testGetZoneAsIdentityClient() throws Exception  {
        String id = generator.generate();
        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken);
        IdentityZone retrieved = getIdentityZone(id, HttpStatus.OK, identityClientToken);
        assertEquals(created.getId(), retrieved.getId());
        assertEquals(created.getName(), retrieved.getName());
        assertEquals(created.getSubdomain(), retrieved.getSubdomain());
        assertEquals(created.getDescription(), retrieved.getDescription());
    }

    @Test
    public void testGetZoneThatDoesntExist() throws Exception  {
        String id = generator.generate();
        getIdentityZone(id, HttpStatus.NOT_FOUND, identityClientToken);
    }

    @Test
    public void testCreateZone() throws Exception {
        String id = generator.generate();
        IdentityZone zone = createZone(id, HttpStatus.CREATED, identityClientToken);
        assertEquals(id, zone.getId());
        assertEquals(id, zone.getSubdomain());
        checkAuditEventListener(1, AuditEventType.IdentityZoneCreatedEvent);
    }

    @Test
    public void testCreateZoneInsufficientScope() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        createZone(id, HttpStatus.FORBIDDEN, adminToken);

        assertEquals(0, eventListener.getEventCount());
    }

    @Test
    public void testCreateZoneNoToken() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        createZone(id, HttpStatus.UNAUTHORIZED, "");

        assertEquals(0, eventListener.getEventCount());
    }


    @Test
    public void testCreateZoneWithoutID() throws Exception {
        IdentityZone zone = createZone("", HttpStatus.CREATED, identityClientToken);
        assertTrue(StringUtils.hasText(zone.getId()));

        checkAuditEventListener(1, AuditEventType.IdentityZoneCreatedEvent);
    }

    @Test
    public void testUpdateNonExistentReturns403() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        IdentityZone identityZone = getIdentityZone(id);
        //zone doesn't exist and we don't have the token scope
        updateZone(identityZone, HttpStatus.FORBIDDEN, adminToken);

        assertEquals(0, eventListener.getEventCount());
    }

    @Test
    public void testUpdateUaaIsForbidden() throws Exception {
        updateZone(IdentityZone.getUaa(), HttpStatus.FORBIDDEN, identityClientToken);
        checkAuditEventListener(0, AuditEventType.IdentityZoneModifiedEvent);
    }

    @Test
    public void testUpdateNonExistentReturns404() throws Exception {
        String id = generator.generate();
        IdentityZone identityZone = getIdentityZone(id);
        updateZone(identityZone, HttpStatus.NOT_FOUND, identityClientToken);

        assertEquals(0, eventListener.getEventCount());
    }

    @Test
    public void testUpdateWithSameDataReturns200() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken);
        checkAuditEventListener(1, AuditEventType.IdentityZoneCreatedEvent);

        updateZone(created, HttpStatus.OK, identityClientToken);
        checkAuditEventListener(2, AuditEventType.IdentityZoneModifiedEvent);
    }

    @Test
    public void testUpdateWithDifferentDataReturns200() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken);

        checkAuditEventListener(1, AuditEventType.IdentityZoneCreatedEvent);
        created.setDescription("updated description");
        IdentityZone updated = updateZone(created, HttpStatus.OK, identityClientToken);
        assertEquals("updated description", updated.getDescription());
        checkAuditEventListener(2, AuditEventType.IdentityZoneModifiedEvent);
    }

    @Test
    public void testUpdateZoneWithExistingSubdomain() throws Exception {
        String id1 = generator.generate();
        IdentityZone created1 = createZone(id1, HttpStatus.CREATED, identityClientToken);
        checkAuditEventListener(1, AuditEventType.IdentityZoneCreatedEvent);

        String id2 = generator.generate();
        IdentityZone created2 = createZone(id2, HttpStatus.CREATED, identityClientToken);
        checkAuditEventListener(2, AuditEventType.IdentityZoneCreatedEvent);

        created1.setSubdomain(created2.getSubdomain());
        updateZone(created1, HttpStatus.CONFLICT, identityClientToken);

        checkAuditEventListener(2, AuditEventType.IdentityZoneCreatedEvent);
    }

    @Test
    public void testUpdateZoneNoToken() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        IdentityZone identityZone = getIdentityZone(id);
        updateZone(identityZone, HttpStatus.UNAUTHORIZED, "");

        assertEquals(0, eventListener.getEventCount());
    }

    @Test
    public void testUpdateZoneInsufficientScope() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        IdentityZone identityZone = getIdentityZone(id);
        updateZone(identityZone, HttpStatus.FORBIDDEN, adminToken);

        assertEquals(0, eventListener.getEventCount());
    }

    @Test
    public void testCreateDuplicateZoneReturns409() throws Exception {
        String id = generator.generate();
        createZone(id, HttpStatus.CREATED, identityClientToken);

        checkAuditEventListener(1, AuditEventType.IdentityZoneCreatedEvent);

        createZone(id, HttpStatus.CONFLICT, identityClientToken);

        assertEquals(1, eventListener.getEventCount());
    }

    @Test
    public void testCreateZoneAndIdentityProvider() throws Exception {
        IdentityZoneCreationRequest creationRequest = new IdentityZoneCreationRequest();
        String id = UUID.randomUUID().toString();
        IdentityZone identityZone = getIdentityZone(id);
        creationRequest.setIdentityZone(identityZone);

        mockMvc.perform(post("/identity-zones")
            .header("Authorization", "Bearer "+identityClientToken)
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(creationRequest)))
            .andExpect(status().isCreated())
            .andReturn();

        checkAuditEventListener(1, AuditEventType.IdentityZoneCreatedEvent);


        IdentityProviderProvisioning idpp = (IdentityProviderProvisioning) webApplicationContext.getBean("identityProviderProvisioning");
        IdentityProvider idp1 = idpp.retrieveByOrigin(Origin.UAA, identityZone.getId());


        IdentityProvider idp2 = idpp.retrieveByOrigin(Origin.UAA, IdentityZone.getUaa().getId());
        assertNotEquals(idp1,  idp2);
    }

    private IdentityZone getIdentityZone(String id) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setSubdomain(StringUtils.hasText(id)?id:new RandomValueStringGenerator().generate());
        identityZone.setName("The Twiglet Zone");
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        return identityZone;
    }

    @Test
    public void testCreateInvalidZone() throws Exception {
        IdentityZone identityZone = new IdentityZone();
        IdentityZoneCreationRequest creationRequest = new IdentityZoneCreationRequest();
        creationRequest.setIdentityZone(identityZone);
        mockMvc.perform(post("/identity-zones")
            .header("Authorization", "Bearer "+identityClientToken)
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(creationRequest)))
            .andExpect(status().isBadRequest());

        assertEquals(0, eventListener.getEventCount());
    }



    @Test
    public void testCreatesZonesWithDuplicateSubdomains() throws Exception {
        String subdomain = UUID.randomUUID().toString();
        String id1 = UUID.randomUUID().toString();
        String id2 = UUID.randomUUID().toString();
        IdentityZone identityZone1 = MultitenancyFixture.identityZone(id1, subdomain);
        IdentityZone identityZone2 = MultitenancyFixture.identityZone(id2, subdomain);
        IdentityZoneCreationRequest creationRequest = new IdentityZoneCreationRequest();
        creationRequest.setIdentityZone(identityZone1);
        mockMvc.perform(post("/identity-zones")
            .header("Authorization", "Bearer "+identityClientToken)
            .contentType(APPLICATION_JSON)
            .accept(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(creationRequest)))
            .andExpect(status().isCreated());

        checkAuditEventListener(1, AuditEventType.IdentityZoneCreatedEvent);

        creationRequest.setIdentityZone(identityZone2);
        mockMvc.perform(post("/identity-zones")
            .header("Authorization", "Bearer "+identityClientToken)
            .contentType(APPLICATION_JSON)
            .accept(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(creationRequest)))
            .andExpect(status().isConflict());

        assertEquals(1, eventListener.getEventCount());
    }

    @Test
    public void testCreateZoneAndClients() throws Exception {
        final String id = UUID.randomUUID().toString();
        IdentityZone identityZone = getIdentityZone(id);
        IdentityZoneCreationRequest creationRequest = new IdentityZoneCreationRequest();
        creationRequest.setIdentityZone(identityZone);
        List<BaseClientDetails> clientDetails = new ArrayList<>();
        BaseClientDetails client1 = new BaseClientDetails("client1", null,null, "client_credentials", "clients.admin,scim.read,scim.write");
        client1.setClientSecret("client1Secret");
        clientDetails.add(client1);
        BaseClientDetails client2 = new BaseClientDetails("client2", null,null, "client_credentials", "clients.admin,scim.read,scim.write");
        client2.setClientSecret("client2Secret");
        clientDetails.add(client2);
        creationRequest.setClientDetails(clientDetails);

        mockMvc.perform(post("/identity-zones")
            .header("Authorization", "Bearer "+identityClientToken)
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(creationRequest)))
            .andExpect(status().isCreated());

        checkAuditEventListener(1, AuditEventType.IdentityZoneCreatedEvent);

        mockMvc.perform(get("/oauth/token?grant_type=client_credentials")
                    .header("Authorization", getBasicAuthHeaderValue(client1.getClientId(), client1.getClientSecret()))
                    .with(new SetServerNameRequestPostProcessor(id+".localhost")))
                .andExpect(status().isOk())
                .andReturn();

        mockMvc.perform(get("/oauth/token?grant_type=client_credentials")
                    .header("Authorization", getBasicAuthHeaderValue(client2.getClientId(), client2.getClientSecret()))
                    .with(new SetServerNameRequestPostProcessor(id+".localhost")))
                .andExpect(status().isOk())
                .andReturn();

    }

    @Test
    public void testSuccessfulUserManagementInZone() throws Exception {
        String subdomain = generator.generate();
        createOtherIdentityZone(subdomain);

        checkAuditEventListener(1, AuditEventType.IdentityZoneCreatedEvent);

        String zoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "admin-secret", "scim.write,scim.read", subdomain);
        ScimUser user = createUser(zoneAdminToken, subdomain);

        user.setUserName("updated-username@test.com");
        MockHttpServletRequestBuilder put = put("/Users/" + user.getId())
            .header("Authorization", "Bearer " + zoneAdminToken)
            .header("If-Match", "\"" + user.getVersion() + "\"")
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(user))
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));

        MvcResult result = mockMvc.perform(put)
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.userName").value(user.getUserName()))
            .andReturn();
        user = new ObjectMapper().readValue(result.getResponse().getContentAsString(), ScimUser.class);

        List<ScimUser> users = getUsersInZone(subdomain, zoneAdminToken);
        assertTrue(users.contains(user));
        assertEquals(1, users.size());

        MockHttpServletRequestBuilder delete = delete("/Users/" + user.getId())
            .header("Authorization", "Bearer " + zoneAdminToken)
            .header("If-Match", "\"" + user.getVersion() + "\"")
            .contentType(APPLICATION_JSON)
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));

        mockMvc.perform(delete)
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(user.getId()))
            .andReturn();

        users = getUsersInZone(subdomain, zoneAdminToken);
        assertEquals(0, users.size());
    }

    private List<ScimUser> getUsersInZone(String subdomain, String token) throws Exception {
        MockHttpServletRequestBuilder get = get("/Users").header("Authorization", "Bearer " + token);
        if (subdomain != null && !subdomain.equals("")) get.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));

        MvcResult mvcResult = mockMvc.perform(get).andExpect(status().isOk()).andReturn();

        JsonNode root = new ObjectMapper().readTree(mvcResult.getResponse().getContentAsString());
        return new ObjectMapper().readValue(root.get("resources").toString(), new TypeReference<List<ScimUser>>() {});
    }

    @Test
    public void testCreateAndListUsersInOtherZoneIsUnauthorized() throws Exception {
        String subdomain = generator.generate();
        createOtherIdentityZone(subdomain);

        checkAuditEventListener(1, AuditEventType.IdentityZoneCreatedEvent);

        String defaultZoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.write,scim.read");

        ScimUser user = getScimUser();

        byte[] requestBody = new ObjectMapper().writeValueAsBytes(user);
        MockHttpServletRequestBuilder post = post("/Users")
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .header("Authorization", "Bearer " + defaultZoneAdminToken)
            .contentType(APPLICATION_JSON)
            .content(requestBody);

        mockMvc.perform(post).andExpect(status().isUnauthorized());

        MockHttpServletRequestBuilder get = get("/Users").header("Authorization", "Bearer " + defaultZoneAdminToken);
        if (subdomain != null && !subdomain.equals("")) get.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));

        mockMvc.perform(get).andExpect(status().isUnauthorized()).andReturn();
    }

    @Test
    public void testModifyandDeleteUserInOtherZoneIsUnauthorized() throws Exception {
        String defaultZoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.write");
        ScimUser user = createUser(defaultZoneAdminToken, null);

        String subdomain = generator.generate();
        createOtherIdentityZone(subdomain);

        checkAuditEventListener(1, AuditEventType.IdentityZoneCreatedEvent);

        String zoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "admin-secret", "scim.write,scim.read", subdomain);
        user.setUserName("updated-user@defaultzone.com");

        MockHttpServletRequestBuilder put = put("/Users/" + user.getId())
            .header("Authorization", "Bearer " + zoneAdminToken)
            .header("If-Match", "\"" + user.getVersion() + "\"")
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(user));

        mockMvc.perform(put)
            .andExpect(status().isUnauthorized())
            .andReturn();

        MockHttpServletRequestBuilder delete = delete("/Users/" + user.getId())
            .header("Authorization", "Bearer " + zoneAdminToken)
            .header("If-Match", "\"" + user.getVersion() + "\"")
            .contentType(APPLICATION_JSON);

        mockMvc.perform(delete)
            .andExpect(status().isUnauthorized())
            .andReturn();
    }

    private IdentityZone getIdentityZone(String id, HttpStatus expect, String token) throws Exception {
        MvcResult result = mockMvc.perform(get("/identity-zones/"+id)
            .header("Authorization", "Bearer " + token))
            .andExpect(status().is(expect.value()))
            .andReturn();

        if (expect.is2xxSuccessful()) {
            return JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityZone.class);
        }
        return null;
    }

    private IdentityZone createZone(String id, HttpStatus expect, String token) throws Exception {
        IdentityZone identityZone = getIdentityZone(id);
        IdentityZoneCreationRequest creationRequest = new IdentityZoneCreationRequest();
        creationRequest.setIdentityZone(identityZone);
        MvcResult result = mockMvc.perform(post("/identity-zones")
            .header("Authorization", "Bearer " + token)
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(creationRequest)))
            .andExpect(status().is(expect.value()))
            .andReturn();

        if (expect.is2xxSuccessful()) {
            return JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityZone.class);
        }
        return null;
    }

    private IdentityZone updateZone(IdentityZone identityZone, HttpStatus expect, String token) throws Exception {
        IdentityZoneCreationRequest creationRequest = new IdentityZoneCreationRequest();
        creationRequest.setIdentityZone(identityZone);
        MvcResult result = mockMvc.perform(put("/identity-zones/" + identityZone.getId())
            .header("Authorization", "Bearer " + token)
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(creationRequest)))
            .andExpect(status().is(expect.value()))
            .andReturn();

        if (expect.is2xxSuccessful()) {
            return JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityZone.class);
        }
        return null;
    }


    private IdentityZone createOtherIdentityZone(String subdomain) throws Exception {

        String identityToken = testClient.getClientCredentialsOAuthAccessToken("identity", "identitysecret", "zones.create");

        IdentityZone identityZone = MultitenancyFixture.identityZone(subdomain, subdomain);
        IdentityZoneCreationRequest creationRequest = new IdentityZoneCreationRequest();
        creationRequest.setIdentityZone(identityZone);

        List<BaseClientDetails> clientDetails = new ArrayList<>();
        BaseClientDetails client = new BaseClientDetails("admin", null,null, "client_credentials", "clients.admin,scim.read,scim.write");
        client.setClientSecret("admin-secret");
        clientDetails.add(client);
        creationRequest.setClientDetails(clientDetails);

        mockMvc.perform(post("/identity-zones")
            .header("Authorization", "Bearer " + identityToken)
            .contentType(APPLICATION_JSON)
            .accept(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(creationRequest)))
            .andExpect(status().isCreated());

        return identityZone;
    }

    private String getBasicAuthHeaderValue(String clientId, String clientSecret) {
        final String plainCreds = clientId+":"+clientSecret;
        final byte[] plainCredsBytes = plainCreds.getBytes();
        final byte[] base64CredsBytes = Base64.encodeBase64(plainCredsBytes);
        final String base64Creds = new String(base64CredsBytes);
        return "Basic "+base64Creds;
    }

    private void checkAuditEventListener(int eventCount, AuditEventType eventType) {
        IdentityZoneModifiedEvent event = eventListener.getLatestEvent();
        assertEquals(eventCount, eventListener.getEventCount());
        if (eventCount > 0) {
            assertEquals(eventType, event.getAuditEvent().getType());
        }
    }
}
