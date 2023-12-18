import "pe"

rule INDICATOR_KB_CERT_53e1f226cb77574f8fbeb5682da091bb
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d247ec7e224a24683da3f138112ffc9607f83c917d6c45494dd744d732249260"
		reason = "SystemBC"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OdyLab Inc" and pe.signatures[i].serial=="53:e1:f2:26:cb:77:57:4f:8f:be:b5:68:2d:a0:91:bb")
}
