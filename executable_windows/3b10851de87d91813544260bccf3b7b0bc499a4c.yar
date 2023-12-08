import "pe"

rule INDICATOR_KB_CERT_008b7369b2f0c313634a1c1dfc4a828a54
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "1cad5864bcc0f6aa20b99a081501a104b633dddd"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LFpKdFUgpGKj" and pe.signatures[i].serial=="00:8b:73:69:b2:f0:c3:13:63:4a:1c:1d:fc:4a:82:8a:54")
}
