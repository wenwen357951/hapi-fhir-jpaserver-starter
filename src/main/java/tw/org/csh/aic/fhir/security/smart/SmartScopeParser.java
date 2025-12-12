package tw.org.csh.aic.fhir.security.smart;

import tw.org.csh.aic.fhir.security.smart.enums.SmartScopeActor;
import tw.org.csh.aic.fhir.security.smart.enums.SmartScopeOperator;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SmartScopeParser {
	private static final Pattern SMART_SCOPE_PATTERN =
		Pattern.compile("^(patient|user|system)/(\\*|[^.]+)\\.([cruds]+)$");

	public static Optional<SmartScope> parse(String raw) {
		String s = raw.startsWith("SCOPE_")
			? raw.substring("SCOPE_".length())
			: raw;

		Matcher m = SMART_SCOPE_PATTERN.matcher(s);
		if (!m.matches()) return Optional.empty(); // openid/launch/profile... 會直接被忽略

		SmartScopeActor actor = SmartScopeActor.from(m.group(1));
		String resource = m.group(2);

		EnumSet<SmartScopeOperator> operators = EnumSet.noneOf(SmartScopeOperator.class);
		for (char chr : m.group(3).toCharArray()) {
			operators.add(SmartScopeOperator.fromChar(chr)); // crs -> {CREATE, READ, SEARCH}
		}

		return Optional.of(new SmartScope(actor, resource, operators));
	}
}
