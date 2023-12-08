import "pe"

rule INDICATOR_KB_CERT_00f8c2e08438bb0e9adc955e4b493e5821
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "459ef82eb5756e85922a4687d66bd6a0195834f955ede35ae6c3039d97b00b5f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DocsGen Software Solutions Inc." and pe.signatures[i].serial=="00:f8:c2:e0:84:38:bb:0e:9a:dc:95:5e:4b:49:3e:58:21")
}
