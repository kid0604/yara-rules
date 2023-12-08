import "pe"

rule INDICATOR_KB_CERT_4cdffb4f02c55ae60a099652605da274
{
	meta:
		author = "ditekSHen"
		description = "Enigma Protector Demo Certificate"
		thumbprint = "4a2d33148aadf947775a15f50535842633cc3442"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DEMO" and pe.signatures[i].serial=="4c:df:fb:4f:02:c5:5a:e6:0a:09:96:52:60:5d:a2:74")
}
