import "pe"

rule INDICATOR_KB_CERT_9f2492304fc9c93844dea7e5d6f0ec77
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "33015f23712f36e3ec310cfd1b16649abb645a98"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bbddebeea" and pe.signatures[i].serial=="9f:24:92:30:4f:c9:c9:38:44:de:a7:e5:d6:f0:ec:77")
}
