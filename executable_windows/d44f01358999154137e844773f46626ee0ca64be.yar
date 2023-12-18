import "pe"

rule INDICATOR_KB_CERT_01cf0b0f01b20b70bfaa69722979ef5c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ef10480ab6448e60bdc689fc54cb6cfc4a8e1d39ddc788ce3d060ab4b7d30b59"
		reason = "Ryuk"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PET PLUS PTY LTD" and pe.signatures[i].serial=="01:cf:0b:0f:01:b2:0b:70:bf:aa:69:72:29:79:ef:5c")
}
