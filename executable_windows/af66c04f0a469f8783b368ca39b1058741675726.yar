import "pe"

rule INDICATOR_KB_CERT_79906faf4fbd75baa10b322356a07f6d
{
	meta:
		author = "ditekSHen"
		description = "Detects NetSupport (client) signed executables"
		thumbprint = "f84ec9488bdac5f90db3c474b55e31a8f10a2026"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NetSupport Ltd" and pe.signatures[i].serial=="79:90:6f:af:4f:bd:75:ba:a1:0b:32:23:56:a0:7f:6d")
}
