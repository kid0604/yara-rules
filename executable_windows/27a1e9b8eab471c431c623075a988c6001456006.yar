import "pe"

rule INDICATOR_KB_CERT_21c9a6daff942f2db6a0614d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7dd9acb2ef0402883c65901ebbafd06e5293d391"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ledger SAS" and pe.signatures[i].serial=="21:c9:a6:da:ff:94:2f:2d:b6:a0:61:4d")
}
