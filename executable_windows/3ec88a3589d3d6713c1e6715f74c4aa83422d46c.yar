import "pe"

rule INDICATOR_KB_CERT_1a041db92237c18948109789f627b3cd
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "2315cf802aaf96d11f18766315239016e533bf32"
		hash1 = "a0338becbfe808bc7655d8b6c825e2e99b37945e5d8fc43a83aec479d64f422d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Amitotic" and pe.signatures[i].serial=="1a:04:1d:b9:22:37:c1:89:48:10:97:89:f6:27:b3:cd")
}
