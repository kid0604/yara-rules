import "pe"

rule INDICATOR_KB_CERT_091736d368a5980ebeb433a0ecb49fbb
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "b1c1dc94f0c775deeb46a0a019597c4ac27ab2810e3b3241bdc284d2fccf3eb5"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ELEKSIR, OOO" and pe.signatures[i].serial=="09:17:36:d3:68:a5:98:0e:be:b4:33:a0:ec:b4:9f:bb")
}
