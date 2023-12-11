import "pe"

rule INDICATOR_KB_CERT_0be3f393d1ef0272aed0e2319c1b5dd0
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7745253a3f65311b84d8f64b74f249364d29e765"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Invincea, Inc." and pe.signatures[i].serial=="0b:e3:f3:93:d1:ef:02:72:ae:d0:e2:31:9c:1b:5d:d0")
}
