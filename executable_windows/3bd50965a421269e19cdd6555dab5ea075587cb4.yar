import "pe"

rule INDICATOR_KB_CERT_f0e150c304de35f2e9086185581f4053
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c0a448b9101f48309a8e5a67c11db09da14b54bb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rare Ideas, LLC" and pe.signatures[i].serial=="f0:e1:50:c3:04:de:35:f2:e9:08:61:85:58:1f:40:53")
}
