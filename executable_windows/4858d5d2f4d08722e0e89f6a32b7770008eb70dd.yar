import "pe"

rule INDICATOR_KB_CERT_00b61b8e71514059adc604da05c283e514
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "67ee69f380ca62b28cecfbef406970ddd26cd9be"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "APP DIVISION ApS" and pe.signatures[i].serial=="00:b6:1b:8e:71:51:40:59:ad:c6:04:da:05:c2:83:e5:14")
}
