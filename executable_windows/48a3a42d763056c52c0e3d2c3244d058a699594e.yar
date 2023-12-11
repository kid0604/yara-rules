import "pe"

rule INDICATOR_KB_CERT_1fb984d5a7296ba74445c23ead7d20aa
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c852fc9670391ff077eb2590639051efa42db5c9"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DrWeb Digital LLC" and pe.signatures[i].serial=="1f:b9:84:d5:a7:29:6b:a7:44:45:c2:3e:ad:7d:20:aa")
}
