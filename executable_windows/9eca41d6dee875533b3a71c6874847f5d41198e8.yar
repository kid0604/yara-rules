import "pe"

rule INDICATOR_KB_CERT_00ede6cfbf9fa18337b0fdb49c1f693020
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "a99b52e0999990c2eb24d1309de7d4e522937080"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "START ARCHITECTURE LTD" and pe.signatures[i].serial=="00:ed:e6:cf:bf:9f:a1:83:37:b0:fd:b4:9c:1f:69:30:20")
}
