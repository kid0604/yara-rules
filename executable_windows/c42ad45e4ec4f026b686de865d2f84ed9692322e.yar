import "pe"

rule INDICATOR_KB_CERT_5ad4ce116b131daf8d784c6fab2ea1f1
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "de2dad893fdd49d7c0d498c0260acfb272588a2b"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ORDARA LTD" and pe.signatures[i].serial=="5a:d4:ce:11:6b:13:1d:af:8d:78:4c:6f:ab:2e:a1:f1")
}
