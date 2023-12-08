import "pe"

rule INDICATOR_KB_CERT_6ce7a0c62f27fa98f78853e1ad11173f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "638dc7cd59f1d634c19e4fc2c41b38ae08a1d2e5"
		os = "windows"
		filetype = "executable"

	condition:
		( uint16(0)==0x5a4d or uint32(0)==0xe011cfd0) and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "D&K ENGINEERING" and pe.signatures[i].serial=="6c:e7:a0:c6:2f:27:fa:98:f7:88:53:e1:ad:11:17:3f")
}
