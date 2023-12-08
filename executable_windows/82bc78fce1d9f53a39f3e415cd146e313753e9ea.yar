import "pe"

rule INDICATOR_KB_CERT_082023879112289bf351d297cc8efcfc
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0eb3382177f26e122e44ddd74df262a45ebe8261029bc21b411958a07b06278a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "STA-R TOV" and pe.signatures[i].serial=="08:20:23:87:91:12:28:9b:f3:51:d2:97:cc:8e:fc:fc")
}
