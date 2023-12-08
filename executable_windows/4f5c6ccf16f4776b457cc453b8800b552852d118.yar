import "pe"

rule INDICATOR_KB_CERT_039668034826df47e6207ec9daed57c3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "f98bdfa941ebfa2fe773524e0f9bbe9072873c2f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CHOO FSP, LLC" and pe.signatures[i].serial=="03:96:68:03:48:26:df:47:e6:20:7e:c9:da:ed:57:c3")
}
