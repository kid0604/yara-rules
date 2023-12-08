import "pe"

rule INDICATOR_KB_CERT_425dc3e0ca8bcdce19d00d87e3f0ba28
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c58bc4370fa01d9a7772fa8c0e7c4c6c99b90561"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Protover LLC" and pe.signatures[i].serial=="42:5d:c3:e0:ca:8b:cd:ce:19:d0:0d:87:e3:f0:ba:28")
}
