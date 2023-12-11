import "pe"

rule INDICATOR_KB_CERT_0a55c15f733bf1633e9ffae8a6e3b37d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "591f68885fc805a10996262c93aab498c81f3010"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Osnova OOO" and pe.signatures[i].serial=="0a:55:c1:5f:73:3b:f1:63:3e:9f:fa:e8:a6:e3:b3:7d")
}
