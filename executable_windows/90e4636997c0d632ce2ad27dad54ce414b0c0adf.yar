import "pe"

rule INDICATOR_KB_CERT_0bab6a2aa84b495d9e554a4c42c0126d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "230614366ddac05c9120a852058c24fa89972535"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NOSOV SP Z O O" and pe.signatures[i].serial=="0b:ab:6a:2a:a8:4b:49:5d:9e:55:4a:4c:42:c0:12:6d")
}
