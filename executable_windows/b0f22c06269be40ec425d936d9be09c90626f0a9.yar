import "pe"

rule INDICATOR_KB_CERT_0f9d91c6aba86f4e54cbb9ef57e68346
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "3c92c9274ab6d3dd520b13029a2490c4a1d98bc0"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kaspersky Lab" and pe.signatures[i].serial=="0f:9d:91:c6:ab:a8:6f:4e:54:cb:b9:ef:57:e6:83:46")
}
