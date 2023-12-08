import "pe"

rule INDICATOR_KB_CERT_cbc2af7d82295a8535f3b26b47522640
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "08d2c03d0959905b4b04caee1202b8ed748a8bd0"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Eabfdafffefaccaedaec" and pe.signatures[i].serial=="cb:c2:af:7d:82:29:5a:85:35:f3:b2:6b:47:52:26:40")
}
