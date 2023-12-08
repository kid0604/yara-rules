import "pe"

rule INDICATOR_KB_CERT_5f11c47d3f8c468e5d38279de98078ce
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "29bbee51837dbc00c8e949ff2c0226d4bbb3722c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Atera Networks LTD." and pe.signatures[i].serial=="5f:11:c4:7d:3f:8c:46:8e:5d:38:27:9d:e9:80:78:ce")
}
