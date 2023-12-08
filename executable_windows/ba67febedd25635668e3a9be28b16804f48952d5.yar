import "pe"

rule INDICATOR_KB_CERT_3991d810fb336e5a7d8c2822
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d66e28b6c6a3789f3ee28afbb07e492fbe85f6a7"
		hash = "744bcf7487aaec504d63521abec65f7c605c52e4a0bf511ab61025fd6c90977b"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Nota Inc." and pe.signatures[i].serial=="39:91:d8:10:fb:33:6e:5a:7d:8c:28:22")
}
