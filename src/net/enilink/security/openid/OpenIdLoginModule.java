package net.enilink.security.openid;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import net.enilink.security.callbacks.RealmCallback;
import net.enilink.security.callbacks.RedirectCallback;
import net.enilink.security.callbacks.ResponseCallback;

import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIUtils;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.message.BasicNameValuePair;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.Message;
import org.openid4java.message.MessageException;
import org.openid4java.message.MessageExtension;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.message.pape.PapeMessage;
import org.openid4java.message.pape.PapeRequest;
import org.openid4java.message.pape.PapeResponse;
import org.openid4java.message.sreg.SRegMessage;
import org.openid4java.message.sreg.SRegRequest;
import org.openid4java.message.sreg.SRegResponse;


public class OpenIdLoginModule implements LoginModule {
	class URIBuilder {
		URI uri;
		List<NameValuePair> params = new ArrayList<NameValuePair>();

		public URIBuilder(String url) throws URISyntaxException {
			this.uri = new URI(url);
			params.addAll(URLEncodedUtils.parse(uri, "UTF-8"));
		}

		public void setParameter(String name, String value) {
			params.add(new BasicNameValuePair(name, value));
		}

		public String toURI() throws URISyntaxException {
			String result = new HttpGet(URIUtils.createURI(
					uri.getScheme(),
					uri.getHost(),
					uri.getPort(),
					uri.getPath(),
					params.isEmpty() ? null : URLEncodedUtils.format(params,
							"UTF-8"), null)).getURI().toString();
			return result;
		}
	}

	// initial state
	private Subject subject;
	private CallbackHandler callbackHandler;
	private Map<String, ?> sharedState;
	private Map<String, ?> options;

	// configurable option
	private boolean debug = false;

	// the authentication status
	private boolean succeeded = false;

	// temp state
	private List<Object> tempCredentials = new ArrayList<Object>();
	private List<Principal> tempPrincipals = new ArrayList<Principal>();

	// OpenID specific
	private static final String P_TOKEN = "rap.security.token";
	private static final String P_CLAIMED = "rap.security.claimed";
	private static final int LASTID_AGE = 365 * 24 * 60 * 60; // seconds

	private static final String OPENID_MODE = "openid.mode";
	private static final String OMODE_CANCEL = "cancel";

	private static final String SCHEMA_EMAIL = "http://schema.openid.net/contact/email";
	private static final String SCHEMA_FIRSTNAME = "http://schema.openid.net/namePerson/first";
	private static final String SCHEMA_LASTNAME = "http://schema.openid.net/namePerson/last";

	private ConsumerManager manager;

	/** Maximum age, in seconds, before forcing re-authentication of account. */
	private int papeMaxAuthAge = -1;

	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map<String, ?> sharedState, Map<String, ?> options) {
		this.subject = subject;
		this.callbackHandler = callbackHandler;
		this.sharedState = sharedState;
		this.options = options;
		
		this.manager = new ConsumerManager();

		debug = "true".equalsIgnoreCase((String) options.get("debug"));

		if (debug) {
			System.out.println("\t\t[OpenIdLoginModule] initialize");
		}
	}

	private boolean isAllowedOpenID(final String id) {
		return true;
	}

	private boolean requestRegistration(final AuthRequest aReq) {
		if (AuthRequest.SELECT_ID.equals(aReq.getIdentity())) {
			// We don't know anything about the identity, as the provider
			// will offer the user a way to indicate their identity. Skip
			// any database query operation and assume we must ask for the
			// registration information, in case the identity is new to us.
			return true;

		}
		// We might already have this account on file. Look for it.
		// try {
		// return accountManager.lookup(aReq.getIdentity()) == null;
		// } catch (AccountException e) {
		// log.warn("Cannot determine if user account exists", e);
		// return true;
		// }
		return true;
	}

	protected boolean loginOnResponse() throws LoginException {
		Callback[] callbacks;
		callbacks = new Callback[] { new ResponseCallback() };

		try {
			callbackHandler.handle(callbacks);
		} catch (java.io.IOException ioe) {
			throw new LoginException(ioe.getMessage());
		} catch (UnsupportedCallbackException uce) {
			return false;
		}

		Map<String, String[]> responseParameters = ((ResponseCallback) callbacks[0])
				.getResponseParameters();
		if (responseParameters != null
				&& responseParameters.containsKey("openid.identity")) {
			try {
				verifyAssertions(responseParameters);
				return true;
			} catch (Exception e) {
				throw new LoginException(e.getMessage());
			}
		}

		return false;
	}

	public boolean login() throws LoginException {
		if (debug) {
			System.out.println("\t\t[OpenIdLoginModule] login");
		}

		if (callbackHandler == null) {
			throw new LoginException(
					"No CallbackHandler available to garner authentication information from the user");
		}

		if (loginOnResponse()) {
			return true;
		}

		Callback[] callbacks;
		callbacks = new Callback[] { new TextInputCallback("OpenID: ",
				"<your OpenID>") };

		try {
			callbackHandler.handle(callbacks);
		} catch (java.io.IOException ioe) {
			throw new LoginException(ioe.getMessage());
		} catch (UnsupportedCallbackException uce) {
			throw new LoginException(uce.getMessage()
					+ " not available to garner "
					+ " authentication information " + " from the user");
		}

		String openidIdentifier = ((TextInputCallback) callbacks[0]).getText();

		if (!isAllowedOpenID(openidIdentifier)) {
			throw new FailedLoginException(
					"OpenID provider is not allowed on this site.");
		}

		final State state = init(openidIdentifier, null);
		if (state == null) {
			throw new LoginException("No OpenID provider.");
		}

		final AuthRequest authRequest;
		try {
			authRequest = manager.authenticate(state.discovered,
					state.retTo.toURI());
			authRequest.setRealm(state.contextUrl);

			if (requestRegistration(authRequest)) {
				final SRegRequest sregReq = SRegRequest.createFetchRequest();
				sregReq.addAttribute("fullname", true);
				sregReq.addAttribute("email", true);
				authRequest.addExtension(sregReq);

				final FetchRequest fetch = FetchRequest.createFetchRequest();
				fetch.addAttribute("FirstName", SCHEMA_FIRSTNAME, true);
				fetch.addAttribute("LastName", SCHEMA_LASTNAME, true);
				fetch.addAttribute("Email", SCHEMA_EMAIL, true);
				authRequest.addExtension(fetch);
			}

			if (0 <= papeMaxAuthAge) {
				final PapeRequest pape = PapeRequest.createPapeRequest();
				pape.setMaxAuthAge(papeMaxAuthAge);
				authRequest.addExtension(pape);
			}
		} catch (URISyntaxException e) {
			throw new LoginException("Cannot create OpenID redirect for "
					+ openidIdentifier + ": " + e.getMessage());
		} catch (MessageException e) {
			throw new LoginException("Cannot create OpenID redirect for "
					+ openidIdentifier + ": " + e.getMessage());
		} catch (ConsumerException e) {
			throw new LoginException("Cannot create OpenID redirect for "
					+ openidIdentifier + ": " + e.getMessage());
		}

		@SuppressWarnings("unchecked")
		Map<String, String> parameterMap = authRequest.getParameterMap();
		callbacks = new Callback[] { new RedirectCallback(
				authRequest.getDestinationUrl(true), parameterMap) };
		try {
			callbackHandler.handle(callbacks);
		} catch (java.io.IOException ioe) {
			throw new LoginException(ioe.getMessage());
		} catch (UnsupportedCallbackException uce) {
			throw new LoginException(uce.getMessage()
					+ " not available to garner "
					+ " authentication information " + " from the user");
		}

		return loginOnResponse();
	}

	<T> T getFirst(T[] values) {
		return values == null || values.length == 0 ? null : values[0];
	}

	void verifyAssertions(Map<String, String[]> parameters) throws Exception {
		if (OMODE_CANCEL.equals(parameters.get(OPENID_MODE))) {
			throw new LoginException("Login canceled by user.");
		}

		// Process the authentication response.
		final String openidIdentifier = getFirst(parameters
				.get("openid.identity"));
		final String claimedIdentifier = getFirst(parameters.get(P_CLAIMED));
		final String returnToken = getFirst(parameters.get(P_TOKEN));
		final String rediscoverIdentifier = claimedIdentifier != null ? claimedIdentifier
				: openidIdentifier;
		final State state;

		if (!isAllowedOpenID(rediscoverIdentifier)
				|| !isAllowedOpenID(openidIdentifier)
				|| (claimedIdentifier != null && !isAllowedOpenID(claimedIdentifier))) {
			throw new LoginException("Provider not allowed");
		}

		state = init(rediscoverIdentifier, returnToken);
		if (state == null) {
			// Re-discovery must have failed, we can't run a login.
			throw new LoginException();
		}

		final String returnTo = getFirst(parameters.get("openid.return_to"));
		if (returnTo != null && returnTo.contains("openid.rpnonce=")) {
			// Some providers (claimid.com) seem to embed these request
			// parameters into our return_to URL, and then give us them
			// in the return_to request parameter. But not all.
			state.retTo.setParameter("openid.rpnonce",
					getFirst(parameters.get("openid.rpnonce")));
			state.retTo.setParameter("openid.rpsig",
					getFirst(parameters.get("openid.rpsig")));
		}

		final VerificationResult result = manager.verify(state.retTo.toURI(),
				new ParameterList(parameters), state.discovered);
		if (result.getVerifiedId() == null /* authentication failure */) {
			if ("Nonce verification failed.".equals(result.getStatusMsg())) {
				// We might be suffering from clock skew on this system.
				throw new LoginException("OpenID failure: "
						+ result.getStatusMsg()
						+ " Likely caused by clock skew on this server,"
						+ " install/configure NTP.");
			} else if (result.getStatusMsg() != null) {
				// Authentication failed.
				throw new LoginException("OpenID failure: "
						+ result.getStatusMsg());
			} else {
				// Assume authentication was canceled.
				throw new LoginException(
						"Authentication canceled for unknown reason.");
			}
		}

		final Message authRsp = result.getAuthResponse();
		SRegResponse sregRsp = null;
		FetchResponse fetchRsp = null;

		if (0 <= papeMaxAuthAge) {
			PapeResponse ext;
			boolean unsupported = false;

			try {
				ext = (PapeResponse) authRsp
						.getExtension(PapeMessage.OPENID_NS_PAPE);
			} catch (MessageException err) {
				// Far too many providers are unable to provide PAPE extensions
				// right now. Instead of blocking all of them log the error and
				// let the authentication complete anyway.
				// log.error("Invalid PAPE response " + openidIdentifier + ": "
				// + err);
				unsupported = true;
				ext = null;
			}
			if (!unsupported && ext == null) {
				// log.error("No PAPE extension response from " +
				// openidIdentifier);
				throw new LoginException(
						"OpenID provider does not support PAPE.");
			}
		}

		if (authRsp.hasExtension(SRegMessage.OPENID_NS_SREG)) {
			final MessageExtension ext = authRsp
					.getExtension(SRegMessage.OPENID_NS_SREG);
			if (ext instanceof SRegResponse) {
				sregRsp = (SRegResponse) ext;
			}
		}

		if (authRsp.hasExtension(AxMessage.OPENID_NS_AX)) {
			final MessageExtension ext = authRsp
					.getExtension(AxMessage.OPENID_NS_AX);
			if (ext instanceof FetchResponse) {
				fetchRsp = (FetchResponse) ext;
			}
		}

		OpenIdCredential c = new OpenIdCredential();
		// TODO: are there actual credentials to be set?
		// c.setProperty("something", null);
		tempCredentials.add(c);

		final StringBuilder n = new StringBuilder();
		if (sregRsp != null) {
			n.append(sregRsp.getAttributeValue("fullname"));
			// areq.setEmailAddress(sregRsp.getAttributeValue("email"));
		} else if (fetchRsp != null) {
			final String firstName = fetchRsp.getAttributeValue("FirstName");
			final String lastName = fetchRsp.getAttributeValue("LastName");
			if (firstName != null && firstName.length() > 0) {
				n.append(firstName);
			}
			if (lastName != null && lastName.length() > 0) {
				if (n.length() > 0) {
					n.append(' ');
				}
				n.append(lastName);
			}
		}

		if (n.length() == 0) {
			// user name could not be retrieved from OpenID provider
			Callback[] callbacks;
			callbacks = new Callback[] { new TextInputCallback(
					"Please enter your name: ", "<your name>") };

			callbackHandler.handle(callbacks);

			String nameText = ((TextInputCallback) callbacks[0]).getText();
			if (nameText != null) {
				n.append(nameText);
			}
		}

		OpenIdPrincipal p = new OpenIdPrincipal(openidIdentifier, n.toString());
		this.tempPrincipals.add(p);

		succeeded = true;
	}

	private State init(final String openidIdentifier, final String returnToken)
			throws LoginException {
		final List<?> list;
		try {
			list = manager.discover(openidIdentifier);
		} catch (DiscoveryException e) {
			throw new LoginException("Cannot discover OpenID "
					+ openidIdentifier + ": " + e.getMessage());
		}
		if (list == null || list.isEmpty()) {
			return null;
		}

		final RealmCallback realm = getRealm();
		final DiscoveryInformation discovered = manager.associate(list);
		try {
			final URIBuilder retTo = new URIBuilder(realm.getApplicationUrl());
			if (returnToken != null && returnToken.length() > 0) {
				retTo.setParameter(P_TOKEN, returnToken);
			}
			if (discovered.hasClaimedIdentifier()) {
				retTo.setParameter(P_CLAIMED, discovered.getClaimedIdentifier()
						.getIdentifier());
			}

			return new State(discovered, retTo, realm.getContextUrl());
		} catch (URISyntaxException e) {
			throw new LoginException(e.getMessage());
		}
	}

	private RealmCallback getRealm() throws LoginException {
		Callback[] callbacks = new Callback[] { new RealmCallback() };
		try {
			callbackHandler.handle(callbacks);
		} catch (java.io.IOException ioe) {
			throw new LoginException(ioe.getMessage());
		} catch (UnsupportedCallbackException uce) {
			throw new LoginException(uce.getMessage()
					+ " not available to garner "
					+ " authentication information.");
		}
		return (RealmCallback) callbacks[0];
	}

	public boolean commit() throws LoginException {
		if (debug) {
			System.out.println("\t\t[OpenIdLoginModule] commit");
		}

		if (succeeded) {
			if (subject.isReadOnly()) {
				throw new LoginException("Subject is read-only");
			}

			try {
				if (debug) {
					for (Principal p : tempPrincipals)
						System.out
								.println("\t\t[OpenIdLoginModule] Principal: "
										+ p);
				}

				subject.getPrincipals().addAll(tempPrincipals);
				subject.getPublicCredentials().addAll(tempCredentials);

				tempPrincipals.clear();
				tempCredentials.clear();

				return true;
			} catch (Exception ex) {
				throw new LoginException(ex.getMessage());
			}
		} else {
			tempPrincipals.clear();
			tempCredentials.clear();
			return true;
		}
	}

	public boolean abort() throws LoginException {
		// if (debug) {
		// System.out.println("\t\t[OpenIdLoginModule] abort");
		// }
		//
		// // Clean up state
		// this.succeeded = false;
		//
		// logout();

		return true;
	}

	public boolean logout() throws LoginException {
		if (debug)
			System.out.println("\t\t[OpenIdLoginModule] logout");

		this.tempPrincipals.clear();
		this.tempCredentials.clear();

		// remove the principals the login module added
		Iterator<OpenIdPrincipal> principals = subject.getPrincipals(
				OpenIdPrincipal.class).iterator();
		while (principals.hasNext()) {
			OpenIdPrincipal p = (OpenIdPrincipal) principals.next();
			if (debug) {
				System.out
						.println("\t\t[OpenIdLoginModule] removing principal "
								+ p.toString());
			}
			subject.getPrincipals().remove(p);
		}

		// remove the credentials the login module added
		Iterator<OpenIdCredential> credentials = subject.getPublicCredentials(
				OpenIdCredential.class).iterator();
		while (credentials.hasNext()) {
			OpenIdCredential c = (OpenIdCredential) credentials.next();
			if (debug)
				System.out
						.println("\t\t[OpenIdLoginModule] removing credential "
								+ c.toString());
			subject.getPublicCredentials().remove(c);
		}

		return true;
	}

	private static class State {
		final DiscoveryInformation discovered;
		final URIBuilder retTo;
		final String contextUrl;

		State(final DiscoveryInformation d, final URIBuilder r, final String c) {
			discovered = d;
			retTo = r;
			contextUrl = c;
		}
	}
}
