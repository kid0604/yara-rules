import "pe"

rule INDICATOR_KB_CERT_65efa92a4164a3a2d888b5cf8ff073c8
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "928246cd6a0ee66095a43ae06a696b4c63c6ac24"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ghisler Software GmbH" and pe.signatures[i].serial=="65:ef:a9:2a:41:64:a3:a2:d8:88:b5:cf:8f:f0:73:c8")
}
