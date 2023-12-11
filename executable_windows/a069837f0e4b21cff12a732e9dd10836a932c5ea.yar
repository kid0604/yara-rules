import "pe"

rule INDICATOR_KB_CERT_Dummy01
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint1 = "16b7eb40b97149f49e8ec885b0a7fa7598f5a00f"
		thumbprint2 = "902bf957b57f134619443d80cb8767250e034110"
		thumbprint3 = "505f0055a66216c81420f41335ea7a4eb7b240fe"
		thumbprint4 = "c05a6806d770dcec780e0477b83f068a1082be06"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dummy certificate" and pe.signatures[i].serial=="01")
}
