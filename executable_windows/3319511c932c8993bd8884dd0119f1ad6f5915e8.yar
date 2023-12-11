import "pe"

rule INDICATOR_KB_CERT_119acead668bad57a48b4f42f294f8f0
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "11ff68da43f0931e22002f1461136c662e623366"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PB03 TRANSPORT LTD." and pe.signatures[i].serial=="11:9a:ce:ad:66:8b:ad:57:a4:8b:4f:42:f2:94:f8:f0")
}
