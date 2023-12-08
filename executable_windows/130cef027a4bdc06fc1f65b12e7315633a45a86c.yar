import "pe"

rule INDICATOR_KB_CERT_51aead5a9ab2d841b449fa82de3a8a00
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "155edd03d034d6958af61bc6a7181ef8f840feae68a236be3ff73ce7553651b0"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Corsair Software Solution Inc." and pe.signatures[i].serial=="51:ae:ad:5a:9a:b2:d8:41:b4:49:fa:82:de:3a:8a:00")
}
