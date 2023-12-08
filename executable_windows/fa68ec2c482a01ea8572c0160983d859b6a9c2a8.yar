import "pe"

rule INDICATOR_KB_CERT_00d609b6c95428954a999a8a99d4f198af
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "b1d8033dd7ad9e82674299faed410817e42c4c40"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Fudl" and pe.signatures[i].serial=="00:d6:09:b6:c9:54:28:95:4a:99:9a:8a:99:d4:f1:98:af")
}
