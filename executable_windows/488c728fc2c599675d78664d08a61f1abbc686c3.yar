import "pe"

rule INDICATOR_KB_CERT_6c8d0cf4d1593ee8dc8d34be71e90251
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d481d73bcf1e45db382d0e345f3badde6735d17d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dbdbecdbdfafdc" and pe.signatures[i].serial=="6c:8d:0c:f4:d1:59:3e:e8:dc:8d:34:be:71:e9:02:51")
}
