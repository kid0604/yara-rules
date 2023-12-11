import "pe"

rule INDICATOR_KB_CERT_4ff4eda5fa641e70162713426401f438
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "a6277cc8fce0f90a1909e6dac8b02a5115dafb40"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DUHANEY LIMITED" and pe.signatures[i].serial=="4f:f4:ed:a5:fa:64:1e:70:16:27:13:42:64:01:f4:38")
}
