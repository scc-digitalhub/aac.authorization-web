package it.smartcommunitylab.aac.authorization.controller;

import static it.smartcommunitylab.aac.authorization.controller.AuthorizationConverter.convert;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import it.smartcommunitylab.aac.authorization.AuthorizationHelper;
import it.smartcommunitylab.aac.authorization.AuthorizationSchemaHelper;
import it.smartcommunitylab.aac.authorization.NotValidResourceException;
import it.smartcommunitylab.aac.authorization.beans.AuthorizationDTO;
import it.smartcommunitylab.aac.authorization.beans.AuthorizationNodeDTO;
import it.smartcommunitylab.aac.authorization.beans.AuthorizationResourceDTO;
import it.smartcommunitylab.aac.authorization.beans.ErrorInfo;
import it.smartcommunitylab.aac.authorization.beans.RequestedAuthorizationDTO;
import it.smartcommunitylab.aac.authorization.model.AuthorizationNodeAlreadyExist;
import it.smartcommunitylab.aac.authorization.model.FQname;

@RestController
@Api(tags = {"AAC Authorization"})
public class AuthorizationController {

	@Autowired
	@Value("${authorization.contextSpace: authorization}")
	private String contextSpace;

	@Autowired
	private AuthorizationHelper authorizationHelper;
	@Autowired
	private AuthorizationSchemaHelper authorizationSchemaHelper;

	@Autowired
	private ResourceServerTokenServices resourceServerTokenServices;
	@Autowired
	private ClientDetailsService clientDetailsService;

	@ApiOperation(value="Delete authorization")
	@RequestMapping(value = "/authorization/{domain}/{id}", method = RequestMethod.DELETE)
	public void removeAuthorization(@RequestHeader("Authorization") String tokenHeader, @PathVariable String domain, @PathVariable String id)
			throws UnauthorizedDomainException {
		checkDomain(tokenHeader, domain);
		authorizationHelper.remove(id);
	}

	@ApiOperation(value="Create authorization")
	@RequestMapping(value = "/authorization/{domain}", method = RequestMethod.POST)
	public AuthorizationDTO insertAuthorization(@RequestHeader("Authorization") String tokenHeader, @PathVariable String domain,
			@RequestBody AuthorizationDTO authorizationDTO)
			throws NotValidResourceException, UnauthorizedDomainException {
		checkDomain(tokenHeader, domain);
		return convert(authorizationHelper.insert(convert(domain, authorizationDTO)));
	}

	@ApiOperation(value="Validate authorization")
	@RequestMapping(value = "/authorization/{domain}/validate", method = RequestMethod.POST)
	public boolean validateAuthorization(@RequestHeader("Authorization") String tokenHeader, @PathVariable String domain,
			@RequestBody RequestedAuthorizationDTO authorization) throws UnauthorizedDomainException {
		checkDomain(tokenHeader, domain);
		return authorizationHelper.validate(convert(domain, authorization));
	}

	@ApiOperation(value="Add authorization schema root element")
	@RequestMapping(value = "/authorization/{domain}/schema", method = RequestMethod.POST)
	public void addRootChildToSchema(@RequestHeader("Authorization") String tokenHeader, @PathVariable String domain,
			@RequestBody AuthorizationNodeDTO node) throws AuthorizationNodeAlreadyExist, UnauthorizedDomainException {
		checkDomain(tokenHeader, domain);
		authorizationSchemaHelper.addRootChild(convert(domain, node));
	}

	@ApiOperation(value="Add authorization schema element")
	@RequestMapping(value = "/authorization/{domain}/schema/{parentQname}", method = RequestMethod.POST)
	public void addChildToSchema(@RequestHeader("Authorization") String tokenHeader, @PathVariable String domain,
			@RequestBody AuthorizationNodeDTO childNode, @PathVariable String parentQname)
			throws AuthorizationNodeAlreadyExist, UnauthorizedDomainException {
		checkDomain(tokenHeader, domain);
		authorizationSchemaHelper.addChild(new FQname(domain, parentQname), convert(domain, childNode));
	}

	@ApiOperation(value="Get authorization schema node")
	@RequestMapping(value = "/authorization/{domain}/schema/{qname}", method = RequestMethod.GET)
	public AuthorizationNodeDTO getNode(@RequestHeader("Authorization") String tokenHeader, @PathVariable String domain,
			@PathVariable String qname) throws UnauthorizedDomainException {
		checkDomain(tokenHeader, domain);
		return convert(authorizationSchemaHelper.getNode(new FQname(domain, qname)));
	}

	@ApiOperation(value="Validate schema resource")
	@RequestMapping(value = "/authorization/{domain}/schema/validate", method = RequestMethod.POST)
	public boolean validateResource(@RequestHeader("Authorization") String tokenHeader, @PathVariable String domain,
			@RequestBody AuthorizationResourceDTO resource) throws UnauthorizedDomainException {
		checkDomain(tokenHeader, domain);
		return authorizationSchemaHelper.isValid(AuthorizationConverter.convert(domain, resource));
	}

	@ApiOperation(value="Load authorization schema")
	@RequestMapping(value = "/authorization/{domain}/schema/load", method = RequestMethod.POST)
	public void loadSchema(@RequestHeader("Authorization") String tokenHeader, @PathVariable String domain,
			org.springframework.http.HttpEntity<String> httpEntity)
			throws UnauthorizedDomainException, AuthorizationNodeAlreadyExist {
		checkDomain(tokenHeader, domain);
		authorizationSchemaHelper.loadJson(httpEntity.getBody());
	}

	private void checkDomain(String header, String domain) throws UnauthorizedDomainException {
		String parsedToken = parseHeaderToken(header);
		OAuth2Authentication auth = resourceServerTokenServices.loadAuthentication(parsedToken);
		String clientId = auth.getOAuth2Request().getClientId();
		ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
		String role = contextSpace + "/" + domain + ":ROLE_PROVIDER";

		if (!client.getAuthorities().stream().anyMatch(a -> role.equals(a.getAuthority()))) {
			throw new UnauthorizedDomainException();
		}
	}

	/**
	 * @param header
	 * @return
	 */
	private String parseHeaderToken(String header) {
		if ((header.toLowerCase().startsWith(OAuth2AccessToken.BEARER_TYPE.toLowerCase()))) {
			String authHeaderValue = header.substring(OAuth2AccessToken.BEARER_TYPE.length()).trim();
			int commaIndex = authHeaderValue.indexOf(',');
			if (commaIndex > 0) {
				authHeaderValue = authHeaderValue.substring(0, commaIndex);
			}
			return authHeaderValue;
		}
		return null;
	}

	@ExceptionHandler(AuthorizationNodeAlreadyExist.class)
	@ResponseStatus(code = HttpStatus.BAD_REQUEST, reason = "authorization node already exists")
	public void authorizationNodeAlreadyExist() {

	}

	@ExceptionHandler(NotValidResourceException.class)
	@ResponseStatus(code = HttpStatus.BAD_REQUEST, reason = "resource in authorization is not valid")
	public void notValidResource() {
	}

	@ExceptionHandler(UnauthorizedDomainException.class)
	@ResponseStatus(code = HttpStatus.UNAUTHORIZED, reason = "not authorized for requested domain")
	public void unauthorizedDomain() {
	}

	@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
	@ExceptionHandler(Exception.class)
	@ResponseBody
	ErrorInfo handleBadRequest(HttpServletRequest req, Exception ex) {
		StackTraceElement ste = ex.getStackTrace()[0];
		return new ErrorInfo(req.getRequestURL().toString(), ex.getClass().getTypeName(), ste.getClassName(),
				ste.getLineNumber());
	}

}
