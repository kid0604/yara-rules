import "pe"

rule INDICATOR_KB_CERT_00b1aea98bf0ce789b6c952310f14edde0
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "28324a9746edbdb41c9579032d6eb6ab4fd3e0906f250d4858ce9c5fe5e97469"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Absolut LLC" and pe.signatures[i].serial=="00:b1:ae:a9:8b:f0:ce:78:9b:6c:95:23:10:f1:4e:dd:e0")
}
