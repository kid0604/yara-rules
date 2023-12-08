import "pe"

rule INDICATOR_KB_CERT_00bdc81bc76090dae0eee2e1eb744a4f9a
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a3b0a1cd3998688f294838758688f96adee7d5aa98ec43709b8868d6914e96c1"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ALM4U GmbH" and pe.signatures[i].serial=="00:bd:c8:1b:c7:60:90:da:e0:ee:e2:e1:eb:74:4a:4f:9a")
}
