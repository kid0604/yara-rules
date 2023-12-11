import "pe"

rule INDICATOR_KB_CERT_899e32c9bf2b533b9275c39f8f9ff96d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "329af76d7c84a90f2117893adc255115c3c961c7"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Eecaaffcbfdffaedcfec" and pe.signatures[i].serial=="89:9e:32:c9:bf:2b:53:3b:92:75:c3:9f:8f:9f:f9:6d")
}
