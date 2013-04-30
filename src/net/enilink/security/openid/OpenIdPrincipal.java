package net.enilink.security.openid;

import java.security.Principal;

public class OpenIdPrincipal implements Principal {
	private String email;
	private String nickname;
	private String url;

	public OpenIdPrincipal(String url) {
		this.url = url;
		this.nickname = null;
		this.email = null;
	}

	public OpenIdPrincipal(String url, String nickname) {
		this.url = url;
		this.nickname = nickname;
		this.email = null;
	}

	public OpenIdPrincipal(String url, String nickname, String email) {
		this.url = url;
		this.nickname = nickname;
		this.email = email;
	}

	public boolean equals(Object o) {
		if (o == null)
			return false;

		if (this == o)
			return true;

		if (o instanceof OpenIdPrincipal) {
			if (((OpenIdPrincipal) o).getName().equals(getName()))
				return true;
			else
				return false;
		} else
			return false;
	}

	public String getEmail() {
		return this.email;
	}

	public String getName() {
		return this.url;
	}

	public String getNickname() {
		return this.nickname;
	}

	public String getOpenIdUrl() {
		return getName();
	}

	public boolean hasEmail() {
		return this.email != null;
	}

	public int hashCode() {
		return getName().hashCode();
	}

	public boolean hasNickname() {
		return this.nickname != null;
	}

	@Override
	public String toString() {
		return getOpenIdUrl();
	}
}
