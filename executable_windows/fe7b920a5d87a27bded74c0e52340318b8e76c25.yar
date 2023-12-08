import "pe"

rule INDICATOR_KB_CERT_0f7e3fda780e47e171864d8f5386bc05
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "1e3dd5576fc57fa2dd778221a60bd33f97087f74"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Louhos Solutions Oy" and pe.signatures[i].serial=="0f:7e:3f:da:78:0e:47:e1:71:86:4d:8f:53:86:bc:05")
}
