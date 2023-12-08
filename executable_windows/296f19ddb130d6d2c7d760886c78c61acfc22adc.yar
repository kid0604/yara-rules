import "pe"

rule INDICATOR_KB_CERT_1f3216f428f850be2c66caa056f6d821
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d4c89b25d3e92d05b44bc32c0cbfd7693613f3ee"
		hash1 = "954f62f0014b51953056dd668441cd4e116874fd6d6c75bd982ba821ea6744eb"
		hash2 = "8fe09855b5eebc5950fdc427fbbd17b2c757a843de687a4da322987510549eba"
		hash3 = "1fbc3ddcd892c868cab037f43fcee5cd1dd67f5ce0ac882d851603bdc934ec43"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Telegram FZ-LLC" and pe.signatures[i].serial=="1f:32:16:f4:28:f8:50:be:2c:66:ca:a0:56:f6:d8:21")
}
