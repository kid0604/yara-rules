import "pe"

rule INDICATOR_KB_CERT_00e38259cf24cc702ce441b683ad578911
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "16304d4840d34a641f58fe7c94a7927e1ba4b3936638164525bedc5a406529f8"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Akhirah Technologies Inc." and pe.signatures[i].serial=="00:e3:82:59:cf:24:cc:70:2c:e4:41:b6:83:ad:57:89:11")
}
