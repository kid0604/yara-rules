import "pe"

rule INDICATOR_KB_CERT_54cd7ae1c27f1421136ed25088f4979a
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "acde047c3d7b22f87d0e6d07fe0a3b734ad5f8ac"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ABBYMAJUTA LTD LIMITED" and pe.signatures[i].serial=="54:cd:7a:e1:c2:7f:14:21:13:6e:d2:50:88:f4:97:9a")
}
