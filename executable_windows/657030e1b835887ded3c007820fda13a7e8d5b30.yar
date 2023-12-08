import "pe"

rule INDICATOR_KB_CERT_041868dd49840ff44f8e3d3070568350
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e104f236e3ee7d21a0ea8053fe8fc5c412784079"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Zhuhai Kingsoft Office Software Co., Ltd." and pe.signatures[i].serial=="04:18:68:dd:49:84:0f:f4:4f:8e:3d:30:70:56:83:50")
}
