import "pe"

rule INDICATOR_KB_CERT_03b27d7f4ee21a462a064a17eef70d6c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a278b5c8a9798ee3b3299ec92a4ab618016628ee"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CCL TRADING LIMITED" and pe.signatures[i].serial=="03:b2:7d:7f:4e:e2:1a:46:2a:06:4a:17:ee:f7:0d:6c")
}
