import "pe"

rule INDICATOR_KB_CERT_03e9eb4dff67d4f9a554a422d5ed86f3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "8f2de7e770a8b1e412c2de131064d7a52da62287"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "philandro Software GmbH" and pe.signatures[i].serial=="03:e9:eb:4d:ff:67:d4:f9:a5:54:a4:22:d5:ed:86:f3")
}
