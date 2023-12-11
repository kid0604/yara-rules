import "pe"

rule INDICATOR_KB_CERT_690910dc89d7857c3500fb74bed2b08d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "dfeb986812ba9f2af6d4ff94c5d1128fa50787951c07b4088f099a5701f1a1a4"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OLIMP STROI" and pe.signatures[i].serial=="69:09:10:dc:89:d7:85:7c:35:00:fb:74:be:d2:b0:8d")
}
