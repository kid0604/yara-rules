import "pe"

rule INDICATOR_KB_CERT_0b446546c36525bf5f084f6bbbba7097
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "05cdf79b0effff361dac0363adaa75b066c49de0"
		hash = "3163ffc06848f6c48ac460ab844470ef85a07b847bf187c2c9cb26c14032a1a5"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TeamViewer Germany GmbH" and pe.signatures[i].serial=="0b:44:65:46:c3:65:25:bf:5f:08:4f:6b:bb:ba:70:97" and 1608724800<=pe.signatures[i].not_after)
}
