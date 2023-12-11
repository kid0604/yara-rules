import "pe"

rule INDICATOR_KB_CERT_00fed006fbf85cd1c6ba6b4345b198e1e6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4bc67aca336287ff574978ef3bf67c688f6449f2"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LoL d.o.o." and pe.signatures[i].serial=="00:fe:d0:06:fb:f8:5c:d1:c6:ba:6b:43:45:b1:98:e1:e6")
}
