import "pe"

rule INDICATOR_KB_CERT_0a005d2e2bcd4137168217d8c727747c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "df788aa00eb400b552923518108eb1d4f5b7176b"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Beijing JoinHope Image Technology Ltd." and pe.signatures[i].serial=="0a:00:5d:2e:2b:cd:41:37:16:82:17:d8:c7:27:74:7c")
}
