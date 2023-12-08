import "pe"

rule INDICATOR_KB_CERT_3bcaed3ef678f2f9bf38d09e149b8d70
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "45d598691e79be3c47e1883d4b0e149c13a76932ea630be429b0cfccf3217bc2"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "StarY Media Inc." and pe.signatures[i].serial=="3b:ca:ed:3e:f6:78:f2:f9:bf:38:d0:9e:14:9b:8d:70")
}
