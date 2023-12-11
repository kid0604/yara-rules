import "pe"

rule INDICATOR_KB_CERT_56f008e69a7c4c3feb389c66eaf58259
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a7dc8cb973ef5f54af0889549d84dee51a7db839"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MEDIATEK INC." and pe.signatures[i].serial=="56:f0:08:e6:9a:7c:4c:3f:eb:38:9c:66:ea:f5:82:59")
}
