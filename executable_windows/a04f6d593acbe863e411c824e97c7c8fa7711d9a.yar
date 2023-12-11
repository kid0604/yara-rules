import "pe"

rule INDICATOR_KB_CERT_635517466b67bd4bba805bc67ac3328c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0b3144ec936028cbf5292504ef2a75eea8eb6c1d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MEDIATEK INC." and pe.signatures[i].serial=="63:55:17:46:6b:67:bd:4b:ba:80:5b:c6:7a:c3:32:8c")
}
