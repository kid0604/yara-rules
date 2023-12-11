import "pe"

rule INDICATOR_KB_CERT_7156ec47ef01ab8359ef4304e5af1a05
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "59fe580974e2f813c2a00b4be01acd46c94fdea89a3049433cd5ba5a2d96666d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BOREC, OOO" and pe.signatures[i].serial=="71:56:ec:47:ef:01:ab:83:59:ef:43:04:e5:af:1a:05")
}
