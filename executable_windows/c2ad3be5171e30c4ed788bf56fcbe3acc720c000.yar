import "pe"

rule INDICATOR_KB_CERT_00801689896ed339237464a41a2900a969
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "9b0ab2e7f3514f6372d14b1f7f963c155b18bd24"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GLG Rental ApS" and pe.signatures[i].serial=="00:80:16:89:89:6e:d3:39:23:74:64:a4:1a:29:00:a9:69")
}
