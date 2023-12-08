import "pe"

rule INDICATOR_KB_CERT_020bc03538fbdc792f39d99a24a81b97
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "0ab2629e4e721a65ad35758d1455c1202aa643d3"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GLOBAL PARK HORIZON SP Z O O" and pe.signatures[i].serial=="02:0b:c0:35:38:fb:dc:79:2f:39:d9:9a:24:a8:1b:97")
}
