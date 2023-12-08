import "pe"

rule INDICATOR_KB_CERT_028aa6e7b516c0d155f15d6290a430e3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "adc0e27a6076311553127e50969b7862d3384d35"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Discord Inc." and pe.signatures[i].serial=="02:8a:a6:e7:b5:16:c0:d1:55:f1:5d:62:90:a4:30:e3")
}
