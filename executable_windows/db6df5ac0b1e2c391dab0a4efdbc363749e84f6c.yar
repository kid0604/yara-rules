import "pe"

rule INDICATOR_KB_CERT_3a236f003bdefc0c55aa42d9c6c0b08e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "5ba147ebae6089f99823b1640c305b337b1a4c36"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Assurio" and pe.signatures[i].serial=="3a:23:6f:00:3b:de:fc:0c:55:aa:42:d9:c6:c0:b0:8e")
}
