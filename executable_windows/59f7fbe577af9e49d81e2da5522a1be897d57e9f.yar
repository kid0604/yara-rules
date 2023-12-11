import "pe"

rule INDICATOR_KB_CERT_VMProtect_Client
{
	meta:
		author = "ditekSHen"
		description = "VMProtect Client Certificate"
		thumbprint1 = "2e20b7079e5d83e7987b2605db160d1561a0c07a"
		hash1 = "284dc48fc2a66a1071117e5f7b2ad68fba4aae69f31cf68b6b950e6205b52dc0"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VMProtect Client ")
}
