import "pe"

rule INDICATOR_KB_CERT_04332c16724ffeda5868d22af56aea43
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "cba350fe1847a206580657758ad6813a9977c40e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bespoke Software Solutions Limited" and pe.signatures[i].serial=="04:33:2c:16:72:4f:fe:da:58:68:d2:2a:f5:6a:ea:43")
}
