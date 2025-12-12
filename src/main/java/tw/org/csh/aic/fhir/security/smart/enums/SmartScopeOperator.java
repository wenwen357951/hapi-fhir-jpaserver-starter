package tw.org.csh.aic.fhir.security.smart.enums;

public enum SmartScopeOperator {
	CREATE('c'),
	READ('r'),
	UPDATE('u'),
	DELETE('d'),
	SEARCH('s');

	private final char code;

	SmartScopeOperator(final char code) {
		this.code = code;
	}

	public static SmartScopeOperator fromChar(final char codeStr) {
		return switch (codeStr) {
			case 'c' -> CREATE;
			case 'r' -> READ;
			case 'u' -> UPDATE;
			case 'd' -> DELETE;
			case 's' -> SEARCH;
			default -> throw new IllegalArgumentException("Unknow SMART scope resource operator. Code: " + codeStr);
		};
	}

	public char getCode() {
		return this.code;
	}
}
