import "pe"

rule INDICATOR_KB_CERT_0989c97804c93ec0004e2843
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "98549ae51b7208bda60b7309b415d887c385864b"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Shanghai Hintsoft Co., Ltd." and pe.signatures[i].serial=="09:89:c9:78:04:c9:3e:c0:00:4e:28:43")
}
