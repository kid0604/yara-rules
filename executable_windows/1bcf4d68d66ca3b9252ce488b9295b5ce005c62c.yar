import "pe"

rule INDICATOR_KB_CERT_00ca7d54577243934f665fd1d443855a3d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "2ea2c7625c1a42fff63f0b17cfc4fd0c0f76d7eb45a86b18ec9a630d3d8ad913"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FABO SP Z O O" and pe.signatures[i].serial=="00:ca:7d:54:57:72:43:93:4f:66:5f:d1:d4:43:85:5a:3d")
}
