import "pe"

rule INDICATOR_KB_CERT_c2cbbd946bc3fdb944d522931d61d51a
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with Sordum Software certificate, particularly Defender Control"
		thumbprint = "f5e71628a478a248353bf0177395223d2c5a0e43"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Sordum Software" and pe.signatures[i].serial=="c2:cb:bd:94:6b:c3:fd:b9:44:d5:22:93:1d:61:d5:1a")
}
