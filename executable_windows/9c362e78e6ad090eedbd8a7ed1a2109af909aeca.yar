import "pe"

rule INDICATOR_KB_CERT_17d99cc2f5b29522d422332e681f3e18
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "969932039e8bf3b4c71d9a55119071cfa1c4a41b"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PKV Trading ApS" and pe.signatures[i].serial=="17:d9:9c:c2:f5:b2:95:22:d4:22:33:2e:68:1f:3e:18")
}
