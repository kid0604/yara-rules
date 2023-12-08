import "pe"

rule INDICATOR_KB_CERT_38b0eaa7c533051a456fb96c4ecf91c4
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "8e2e69b1202210dc9d2155a0f974ab8c325d5297"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Marianne Septier" and pe.signatures[i].serial=="38:b0:ea:a7:c5:33:05:1a:45:6f:b9:6c:4e:cf:91:c4")
}
