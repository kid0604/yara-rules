import "pe"

rule INDICATOR_KB_CERT_4152169f22454ed604d03555b7afb175
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a1561cacd844fcb62e9e0a8ee93620b3b7d4c3f4bd6f3d6168129136471a7fdb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SMACKTECH SOFTWARE LIMITED" and pe.signatures[i].serial=="41:52:16:9f:22:45:4e:d6:04:d0:35:55:b7:af:b1:75")
}
