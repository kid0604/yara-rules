import "pe"

rule INDICATOR_KB_CERT_5aa94583a95d42f1
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0b27715d7c78368bca3ac0bb829a7ceb19b3b5c3"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "UInt32" and pe.signatures[i].serial=="5a:a9:45:83:a9:5d:42:f1")
}
