import "pe"

rule INDICATOR_KB_CERT_66390fc17786d4a342f0ee89996d6522
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "80e8620ff16598cc1e157a2b7df17d528b03b6e5"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Logitech Z-" and pe.signatures[i].serial=="66:39:0f:c1:77:86:d4:a3:42:f0:ee:89:99:6d:65:22")
}
