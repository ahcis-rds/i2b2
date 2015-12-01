/*
 * Copyright (c) 2011 - University of Texas Health Science Center at Houston.
 * 7000 Fannin St, Suite 600, Houston, Texas 77030
 * All rights reserved.   This program and the accompanying materials
 * are made available under the terms of the i2b2 Software License v2.1
 * which accompanies this distribution.
 */

package edu.harvard.i2b2.pm.util;

import java.net.UnknownHostException;

import edu.harvard.i2b2.pm.ejb.DBInfoType;
import edu.harvard.i2b2.pm.services.HiveParamData;

import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.*;
import java.util.*;

/*
 * LDAP authentication for i2b2 v1.6
 *
 * @param username String
 * @param password String
 * @param params Hashtable object that holds user parameters for LDAP configuration
 *
 * The parameters are listed below with their possible values in ():
 * authentication_method - (LDAP)
 * connection_url - ()
 * search_base - ()
 * distinguished_name - (uid=), (cn=)
 * ssl - (true)(1)
 * security_authentication - (none), (simple), (DIGEST-MD5), (CRAM-MD5), (EXTERNAL)
 * bind_username - ()
 * bind_password - ()
 * bind_search_base - ()
 * bind_distinguished_name - (uid=), (cn=)
 * security_layer - (auth-conf), (auth-int), (auth-conf,auth-int)
 * privacy_strength - (high), (medium), (low)
 * max_buffer - (0)-(65536)
 *
 * @version    1.0 30 Aug 2011
 * @author     Johnny Phan
 */


public class SecurityAuthenticationLDAP implements SecurityAuthentication {

	@Override
	public boolean validateUser(String username, String password,
			Hashtable params) throws Exception {

		// Initialize variables
		String connectionURL = "", searchBase = "", securityAuthentication = "",
			setSSL = "", dn = "", principalName = "";

		// DIGEST-MD5 variables
		String securityLayer = "", privacyStrength = "", maxBuffer = "";

		// Pre-auth bind variables
		String bindUsername = "", bindPassword = "", bindSearchBase = "",
			bindDn = "", bindPrincipalName = "";

		// Sets the values from the parameters
		connectionURL = (String) params.get("connection_url");
		searchBase = (String) params.get("search_base");
		securityAuthentication = (String) params.get("security_authentication");
		securityAuthentication = securityAuthentication.toUpperCase();
		setSSL = (String) params.get("ssl");
		dn = (String) params.get("distinguished_name");
		principalName = dn + username + "," + searchBase;

		// Pre-auth binding configuration from the parameters
		bindUsername = (String) params.get("bind_username");
		bindPassword = (String) params.get("bind_password");
		bindSearchBase = (String) params.get("bind_search_base");
		bindDn = (String) params.get("bind_distinguished_name");
		bindPrincipalName = bindDn + bindUsername + "," + bindSearchBase;

		// DIGEST-MD5 configuration from the parameters
		securityLayer = (String) params.get("security_layer");
		privacyStrength = (String) params.get("privacy_strength");
		maxBuffer = (String) params.get("max_buffer");

		// Setup environment for creating initial context
		Hashtable env = new Hashtable();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

		// URL of the LDAP server(s)
		env.put(Context.PROVIDER_URL, connectionURL);

		// Specify the security authentication
		env.put(Context.SECURITY_AUTHENTICATION, securityAuthentication);

		// Specify SSL
		if (setSSL != null)
			env.put(Context.SECURITY_PROTOCOL, "ssl");
	
		// DIGEST-MD5 Configurations
		if (securityAuthentication.equalsIgnoreCase("DIGEST-MD5")) {
			if (securityLayer != null)
				env.put("javax.security.sasl.qop", securityLayer);

			if (privacyStrength != null)
				env.put("javax.security.sasl.strength", privacyStrength);

			if (maxBuffer != null)
				env.put("javax.security.sasl.maxbuf", maxBuffer);
		}



		try {
			if(bindUsername != null) {
				// Specify the bind credentials
				env.put(Context.SECURITY_PRINCIPAL, bindPrincipalName);
				env.put(Context.SECURITY_CREDENTIALS, bindPassword);
				
				// Get our initial connection to the LDAP server
				LdapContext ldap_ctx = new InitialLdapContext(env, null);

				// Search for the user in the ldap tree
				NamingEnumeration<?> naming = ldap_ctx.search(
					searchBase,
					"(" + dn + username + ")",
					getSimpleSearchControls());

				// If we didn't find the user return false
				if(!naming.hasMore())
					return false;

				SearchResult res = (SearchResult) naming.next();
				principalName = (String) res.getNameInNamespace();

				naming.close();
			}

			// Specify the credentials			
			env.put(Context.SECURITY_PRINCIPAL, principalName);
			env.put(Context.SECURITY_CREDENTIALS, password);

			// Create the initial directory context
			DirContext ctx = new InitialDirContext(env);

			// SUCCESS
			return true;
		} catch(AuthenticationException authEx) {
			// AUTHENTICATION FAILURE
			throw new Exception (authEx.getMessage());
		} catch(AuthenticationNotSupportedException noSuppEx) {
			// AUTHENTICATION METHOD NOT SUPPORTED
			throw new Exception (noSuppEx.getMessage());
		} catch(NamingException nEx) {
			// NETWORK PROBLEMS?
			throw new Exception (nEx.getMessage());
		}


	}

	private static SearchControls getSimpleSearchControls() {
		SearchControls controls = new SearchControls();
		controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		controls.setTimeLimit(30000);
		return controls;
	}

}
