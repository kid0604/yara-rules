import "pe"

rule INDICATOR_KB_CERT_4d03ae6512b85eab4184ca7f4fa2e49c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0215ff94a5c0d97db82e11f87e0dfb4318acac38"
		hash1 = "18bf017bdd74e8e8f5db5a4dd7ec3409021c7b0d2f125f05d728f3b740132015"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Lenovo IdeaCentre" and pe.signatures[i].serial=="4d:03:ae:65:12:b8:5e:ab:41:84:ca:7f:4f:a2:e4:9c")
}
