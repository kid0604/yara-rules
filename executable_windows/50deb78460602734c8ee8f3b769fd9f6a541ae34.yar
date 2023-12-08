import "pe"

rule INDICATOR_KB_CERT_142aac4217e22b525c8587589773ba9b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "b15a4189dcbb27f9b7ced94bc5ca40b7e62135c3"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial=="14:2a:ac:42:17:e2:2b:52:5c:85:87:58:97:73:ba:9b")
}
