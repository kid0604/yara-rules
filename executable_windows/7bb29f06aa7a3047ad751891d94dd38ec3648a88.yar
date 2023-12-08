import "pe"

rule INDICATOR_KB_CERT_6b0008bbd5eb53f5d9e616c3ed00000008bbd5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a24cff3a026dc6b30fb62fb01dbda704eb07164f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "microsoft.com" and pe.signatures[i].serial=="6b:00:08:bb:d5:eb:53:f5:d9:e6:16:c3:ed:00:00:00:08:bb:d5")
}
