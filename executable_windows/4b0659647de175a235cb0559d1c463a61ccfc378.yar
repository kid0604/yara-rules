import "pe"

rule INDICATOR_KB_CERT_0a1f3a057a1dce4bf7d76d0c7adf837e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "8279b87c89507bc6e209a7bd8b5c24b31fb9a6dc"
		hash = "2df05a70d3ce646285a0f888df15064b4e73034b67e06d9a4f4da680ed62e926"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Beijing Qihu Technology Co., Ltd." and pe.signatures[i].serial=="0a:1f:3a:05:7a:1d:ce:4b:f7:d7:6d:0c:7a:df:83:7e")
}
