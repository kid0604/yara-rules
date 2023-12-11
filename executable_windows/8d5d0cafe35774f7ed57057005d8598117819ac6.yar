import "pe"

rule INDICATOR_KB_CERT_1f23f001458716d435cca1a55d660ec5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "934d9357b6fb96f7fb8c461dd86824b3eed5f44a65c10383fe0be742c8c9b60e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Ringen" and pe.signatures[i].serial=="1f:23:f0:01:45:87:16:d4:35:cc:a1:a5:5d:66:0e:c5")
}
