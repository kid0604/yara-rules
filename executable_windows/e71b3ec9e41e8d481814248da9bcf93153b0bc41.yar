import "pe"

rule INDICATOR_KB_CERT_00c667ffe3a5b0a5ae7cf3a9e41682e91b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "6b66ba34ff01e0dab6e68ba244d991578a69c4ad"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NAILS UNLIMITED LIMITED" and (pe.signatures[i].serial=="c6:67:ff:e3:a5:b0:a5:ae:7c:f3:a9:e4:16:82:e9:1b" or pe.signatures[i].serial=="00:c6:67:ff:e3:a5:b0:a5:ae:7c:f3:a9:e4:16:82:e9:1b"))
}
