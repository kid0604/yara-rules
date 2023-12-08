import "pe"

rule INDICATOR_KB_CERT_1aec3d3f752a38617c1d7a677d0b5591
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "1d41b9f7714f221d76592e403d2fbb0f0310e697"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SILVER d.o.o." and pe.signatures[i].serial=="1a:ec:3d:3f:75:2a:38:61:7c:1d:7a:67:7d:0b:55:91")
}
