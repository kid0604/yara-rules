import "pe"

rule INDICATOR_KB_CERT_627dfdf73a1455de5143a270799e6b7b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7b69ff55d3c39bd7d67a10f341c1443425f0c83f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Zhuhai liancheng Technology Co., Ltd." and pe.signatures[i].serial=="62:7d:fd:f7:3a:14:55:de:51:43:a2:70:79:9e:6b:7b")
}
