package it.smartcommunitylab.aac.authorization.controller;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigFileApplicationContextInitializer;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.AnnotationConfigWebContextLoader;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import it.smartcommunitylab.aac.authorization.AuthorizationHelper;
import it.smartcommunitylab.aac.authorization.AuthorizationSchemaHelper;
import it.smartcommunitylab.aac.authorization.NotValidResourceException;
import it.smartcommunitylab.aac.authorization.beans.AuthorizationNodeValueDTO;
import it.smartcommunitylab.aac.authorization.beans.AuthorizationResourceDTO;
import it.smartcommunitylab.aac.authorization.model.AccountAttribute;
import it.smartcommunitylab.aac.authorization.model.Authorization;
import it.smartcommunitylab.aac.authorization.model.AuthorizationNode;
import it.smartcommunitylab.aac.authorization.model.AuthorizationNodeAlreadyExist;
import it.smartcommunitylab.aac.authorization.model.AuthorizationNodeValue;
import it.smartcommunitylab.aac.authorization.model.AuthorizationUser;
import it.smartcommunitylab.aac.authorization.model.FQname;
import it.smartcommunitylab.aac.authorization.model.RequestedAuthorization;
import it.smartcommunitylab.aac.authorization.model.Resource;

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@ContextConfiguration(classes = {MongoConfig.class,
		AuthorizationControllerTestConfig.class }, loader = AnnotationConfigWebContextLoader.class, initializers = ConfigFileApplicationContextInitializer.class)
public class AuthorizationControllerTest {

	@Autowired
	private WebApplicationContext ctx;

	private MockMvc mockMvc;

	private ObjectMapper jsonMapper;

	@Before
	public void setUp() throws Exception {
		jsonMapper = new ObjectMapper();
		mockMvc = MockMvcBuilders.webAppContextSetup(ctx).build();
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void addRootChild() throws Exception {
		AuthorizationNode node = new AuthorizationNode(new FQname("domain", "A"));
		RequestBuilder request = MockMvcRequestBuilders.post("/authorization/domain/schema")
				.contentType(MediaType.APPLICATION_JSON).content(jsonMapper.writeValueAsString(node))
				.header("Authorization", getToken());
		mockMvc.perform(request).andExpect(MockMvcResultMatchers.status().is2xxSuccessful());
	}

	@Test
	public void addChildAuthorizationNode() throws Exception {
		AuthorizationNode node = new AuthorizationNode(new FQname("domain", "A"));
		RequestBuilder request = MockMvcRequestBuilders.post("/authorization/domain/schema/parent-qname")
				.content(jsonMapper.writeValueAsString(node)).contentType(MediaType.APPLICATION_JSON)
				.header("Authorization", getToken());
		mockMvc.perform(request).andExpect(MockMvcResultMatchers.status().is2xxSuccessful());
	}

	@Test
	public void getSchema() throws Exception {
		RequestBuilder request = MockMvcRequestBuilders.get("/authorization/domain/schema/qname-node")
				.header("Authorization", getToken());
		mockMvc.perform(request).andExpect(MockMvcResultMatchers.status().is2xxSuccessful());
	}

	@Test
	public void loadSchema() throws Exception {
		String json = "{'domain':'domain', 'nodes':[]}";
		RequestBuilder request = MockMvcRequestBuilders.post("/authorization/domain/schema/load")
				.contentType(MediaType.APPLICATION_JSON).content(json).header("Authorization", getToken());
		mockMvc.perform(request).andExpect(MockMvcResultMatchers.status().is2xxSuccessful());
	}

	@Test
	public void getSchemaFail() throws Exception {
		RequestBuilder request = MockMvcRequestBuilders.get("/authorization/test/schema/qname-node")
				.header("Authorization", getToken());
		mockMvc.perform(request).andExpect(MockMvcResultMatchers.status().is4xxClientError());
	}

	@Test
	public void removeAuthorization() throws Exception {
		RequestBuilder request = MockMvcRequestBuilders.delete("/authorization/domain/my-auth").header("Authorization",
				getToken());
		mockMvc.perform(request).andExpect(MockMvcResultMatchers.status().is2xxSuccessful());
	}

	@Test
	public void insertAuthorization() throws Exception {
		Resource resource = new Resource(new FQname("domain", "A"),
				Arrays.asList(new AuthorizationNodeValue("A", "a", "a_value")));
		AccountAttribute subjectAttribute = new AccountAttribute("account", "name", "subject");
		AccountAttribute entityAttribute = new AccountAttribute("account", "name", "entity");
		Authorization auth = new Authorization(new AuthorizationUser(subjectAttribute, "type"), "action", resource,
				new AuthorizationUser(entityAttribute, "type"));
		RequestBuilder request = MockMvcRequestBuilders.post("/authorization/domain")
				.content(jsonMapper.writeValueAsString(auth)).contentType(MediaType.APPLICATION_JSON)
				.header("Authorization", getToken());
		mockMvc.perform(request).andExpect(MockMvcResultMatchers.status().is2xxSuccessful());
	}

	@Test
	public void validateAuthorization() throws Exception {
		Resource resource = new Resource(new FQname("domain", "A"),
				Arrays.asList(new AuthorizationNodeValue("A", "a", "a_value")));
		AccountAttribute subjectAttribute = new AccountAttribute("account", "name", "subject");
		AccountAttribute entityAttribute = new AccountAttribute("account", "name", "entity");
		Authorization auth = new Authorization(new AuthorizationUser(subjectAttribute, "type"), "action", resource,
				new AuthorizationUser(entityAttribute, "type"));
		RequestBuilder request = MockMvcRequestBuilders.post("/authorization/domain/validate")
				.content(jsonMapper.writeValueAsString(auth)).contentType(MediaType.APPLICATION_JSON)
				.header("Authorization", getToken());
		mockMvc.perform(request).andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().string("false"));
	}

	@Test
	public void validateResource() throws Exception {
		AuthorizationNodeValueDTO nodeValue = new AuthorizationNodeValueDTO();
		nodeValue.setName("a");
		nodeValue.setQname("A");
		nodeValue.setValue("a_value");
		AuthorizationResourceDTO resource = new AuthorizationResourceDTO();
		resource.setQnameRef("A");
		resource.setValues(Arrays.asList(nodeValue));
		ObjectMapper jsonMapper = new ObjectMapper();
		RequestBuilder request = MockMvcRequestBuilders.post("/authorization/domain/schema/validate")
				.content(jsonMapper.writeValueAsString(resource)).contentType(MediaType.APPLICATION_JSON)
				.header("Authorization", getToken());
		mockMvc.perform(request).andExpect(MockMvcResultMatchers.status().is2xxSuccessful());
	}

	/**
	 * @return
	 */
	private String getToken() {
		return "Bearer 1234567890";
	}


}

@TestConfiguration
@EnableWebMvc // without it mockMvc post thrown an HTTP 415 ERROR
@ComponentScan(basePackages = { "it.smartcommunitylab.aac" })
class AuthorizationControllerTestConfig {

	/**
	 * 
	 */
	private static final List<SimpleGrantedAuthority> AUTHORITIES = Collections.singletonList(new SimpleGrantedAuthority("authorization/domain:ROLE_PROVIDER"));

	@Bean
	public ResourceServerTokenServices getResourceServerTokenServices() {
		return new ResourceServerTokenServices() {
			
			@Override
			public OAuth2AccessToken readAccessToken(String accessToken) {
				return null;
			}
			
			@Override
			public OAuth2Authentication loadAuthentication(String accessToken)
					throws AuthenticationException, InvalidTokenException {
				
				return new OAuth2Authentication(new OAuth2Request(Collections.emptyMap(), "client", AUTHORITIES, true, null, null, null, null, null), new UsernamePasswordAuthenticationToken("1", ""));
			}
		};
	}
	
	@Bean
	public ClientDetailsService getClientDetailsService() {
		return new ClientDetailsService() {
			
			@Override
			public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
				BaseClientDetails details = new BaseClientDetails();
				details.setAuthorities(AUTHORITIES);
				return details;
			}
		};
	}
	
	@Bean
	public AuthorizationController authorizationController() {
		return new AuthorizationController();
	}

	@Bean
	public AuthorizationHelper authorizationHelper() {
		return new AuthorizationHelper() {

			@Override
			public boolean validate(RequestedAuthorization auth) {
				return false;
			}

			@Override
			public void remove(Authorization auth) {
			}

			@Override
			public Authorization insert(Authorization auth) throws NotValidResourceException {
				return null;
			}

			@Override
			public void remove(String authorizationId) {

			}
		};
	}

	@Bean
	public AuthorizationSchemaHelper authorizationSchemaHelper() {
		return new AuthorizationSchemaHelper() {

			@Override
			public boolean isValid(Resource res) {
				return false;
			}

			@Override
			public AuthorizationNode getNode(FQname qname) {
				return null;
			}

			@Override
			public Set<AuthorizationNode> getChildren(AuthorizationNode node) {
				return null;
			}

			@Override
			public Set<AuthorizationNode> getAllChildren(AuthorizationNode node) {
				return null;
			}

			@Override
			public AuthorizationSchemaHelper addRootChild(AuthorizationNode child)
					throws AuthorizationNodeAlreadyExist {
				return null;
			}

			@Override
			public AuthorizationSchemaHelper addChild(AuthorizationNode parent, AuthorizationNode child)
					throws AuthorizationNodeAlreadyExist {
				return null;
			}

			@Override
			public AuthorizationSchemaHelper addChild(FQname parentQname, AuthorizationNode child)
					throws AuthorizationNodeAlreadyExist {
				return null;
			}

			@Override
			public Set<AuthorizationNode> getChildren(FQname qName) {
				return null;
			}

			@Override
			public Set<AuthorizationNode> getAllChildren(FQname qname) {
				return null;
			}

			@Override
			public void loadJson(String jsonString) {

			}
		};
	}

}
