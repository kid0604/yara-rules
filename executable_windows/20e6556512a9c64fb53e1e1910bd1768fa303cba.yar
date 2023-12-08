import "pe"

rule INDICATOR_KB_CERT_c314a8736f82c411b9f02076a6db4771
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "9c49d7504551ad4ddffad206b095517a386e8a14"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cbcbaeaabbfcebfcbbeeffeadfc" and pe.signatures[i].serial=="c3:14:a8:73:6f:82:c4:11:b9:f0:20:76:a6:db:47:71")
}
