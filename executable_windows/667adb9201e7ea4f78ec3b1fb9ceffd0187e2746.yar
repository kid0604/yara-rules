import "pe"

rule INDICATOR_KB_CERT_5d5d03edb4ec4e185caa3041824ab75c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f6c9c564badc1bbd8a804c5e20ab1a0eff89d4c0"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ffcdcbacfeaedbfbcecccafeb" and pe.signatures[i].serial=="5d:5d:03:ed:b4:ec:4e:18:5c:aa:30:41:82:4a:b7:5c")
}
