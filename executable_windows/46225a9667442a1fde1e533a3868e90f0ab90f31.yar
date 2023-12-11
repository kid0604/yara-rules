import "pe"

rule INDICATOR_KB_CERT_00b8164f7143e1a313003ab0c834562f1f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "263c636c5de68f0cd2adf31b7aebc18a5e00fc47a5e2124e2a5613b9a0247c1e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ekitai Data Inc." and pe.signatures[i].serial=="00:b8:16:4f:71:43:e1:a3:13:00:3a:b0:c8:34:56:2f:1f")
}
