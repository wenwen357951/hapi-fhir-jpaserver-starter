package tw.org.csh.aic.fhir.security.smart.enums;

public enum SmartScopeActor {
	PATIENT,
	USER,
	SYSTEM;

	public static SmartScopeActor from(final String actorStr) {
		return SmartScopeActor.valueOf(actorStr.toUpperCase());
	}
}
