import "pe"

rule INDICATOR_KB_CERT_44fe73f320aa8b7b4f5ca910aa22333a
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e952eb51416ab15c0a38b64a32348ed40b675043"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Alpeks LLC" and pe.signatures[i].serial=="44:fe:73:f3:20:aa:8b:7b:4f:5c:a9:10:aa:22:33:3a")
}
