import "pe"

rule INDICATOR_KB_CERT_07cef66a71c35bc3aed6d100c6493863
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "9f65b1f0bed6e58ecdcc30b81b08b350fcc966a1"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fubon Technologies Ltd" and pe.signatures[i].serial=="07:ce:f6:6a:71:c3:5b:c3:ae:d6:d1:00:c6:49:38:63")
}
