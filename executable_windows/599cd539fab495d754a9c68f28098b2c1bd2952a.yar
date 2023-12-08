import "pe"

rule INDICATOR_KB_CERT_3f8b1d4c656982a34435f971c9f3c301
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f12a12ac95e5c4fa9948dd743cc0e81e46c5222e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Word" and pe.signatures[i].serial=="3f:8b:1d:4c:65:69:82:a3:44:35:f9:71:c9:f3:c3:01")
}
