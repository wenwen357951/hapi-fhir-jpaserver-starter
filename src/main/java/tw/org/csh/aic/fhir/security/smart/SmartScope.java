package tw.org.csh.aic.fhir.security.smart;

import tw.org.csh.aic.fhir.security.smart.enums.SmartScopeActor;
import tw.org.csh.aic.fhir.security.smart.enums.SmartScopeOperator;

import java.util.EnumSet;

public record SmartScope(
	SmartScopeActor actor,
	String resource,
	EnumSet<SmartScopeOperator> operators
) {
}
