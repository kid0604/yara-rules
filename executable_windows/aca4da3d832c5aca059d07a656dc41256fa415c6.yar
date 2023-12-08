import "pe"

rule INDICATOR_KB_CERT_00ef9d0cf071d463cd63d13083046a7b8d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "346849dfdeb9bb1a97d98c62d70c578dacbcf30c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rubin LLC" and pe.signatures[i].serial=="00:ef:9d:0c:f0:71:d4:63:cd:63:d1:30:83:04:6a:7b:8d")
}
