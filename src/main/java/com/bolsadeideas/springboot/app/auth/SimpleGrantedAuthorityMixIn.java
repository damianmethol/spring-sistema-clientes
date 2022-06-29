package com.bolsadeideas.springboot.app.auth;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class SimpleGrantedAuthorityMixIn {

	@JsonCreator
	public SimpleGrantedAuthorityMixIn(@JsonProperty("authority") String role) {

	}

}
