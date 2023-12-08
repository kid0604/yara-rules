import "pe"

rule INDICATOR_KB_CERT_630cf0e612f12805ffa00a41d1032d7c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "107af72db66ec4005ed432e4150a0b6f5a9daf2d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dadebfaca" and pe.signatures[i].serial=="63:0c:f0:e6:12:f1:28:05:ff:a0:0a:41:d1:03:2d:7c")
}
