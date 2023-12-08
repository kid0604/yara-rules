import "pe"

rule INDICATOR_KB_CERT_1ef6392b2993a6f67578299659467ea8
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e87d3e289ccb9f8f9caa53f2aefba102fbf4b231"
		hash1 = "8282e30e3013280878598418b2b274cadc5e00febaa2b93cf25bb438ee6eb032"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ALUSEN d. o. o." and pe.signatures[i].serial=="1e:f6:39:2b:29:93:a6:f6:75:78:29:96:59:46:7e:a8")
}
