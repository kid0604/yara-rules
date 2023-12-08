import "pe"

rule INDICATOR_KB_CERT_00e1e7e596f8f5ccbeed4ab882b6cfe6ce
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4fec400152db868b07f202fd76366332aedc7b78"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LnvNzpvYjsjJOwcvwfalIvRAJHVApnpJU" and pe.signatures[i].serial=="00:e1:e7:e5:96:f8:f5:cc:be:ed:4a:b8:82:b6:cf:e6:ce")
}
