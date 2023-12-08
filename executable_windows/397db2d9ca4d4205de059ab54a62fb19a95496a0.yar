import "pe"

rule INDICATOR_KB_CERT_0393be7fd785ba0e3223a73b15ee6736
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f50fc532839ca7e63315e468c493512db8b7ee83"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FZaKundypKakCIvoMBPpTnwIDUJM" and pe.signatures[i].serial=="03:93:be:7f:d7:85:ba:0e:32:23:a7:3b:15:ee:67:36")
}
