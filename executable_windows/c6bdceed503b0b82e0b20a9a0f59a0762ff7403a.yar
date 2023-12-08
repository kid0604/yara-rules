import "pe"

rule INDICATOR_KB_CERT_f64e5b34dc0e4893495d3b9fd9cde4b7
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "49373674eb2190c227455c9b5833825fe01f957a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMASoft" and pe.signatures[i].serial=="f6:4e:5b:34:dc:0e:48:93:49:5d:3b:9f:d9:cd:e4:b7")
}
