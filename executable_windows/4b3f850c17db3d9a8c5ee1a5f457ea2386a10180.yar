import "pe"

rule INDICATOR_KB_CERT_00ad0a958cdf188bed43154a54bf23afba
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7d851e785ad44eb15d5cdf9c33e10fe8f49616e8"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RHM Ltd" and (pe.signatures[i].serial=="ad:0a:95:8c:df:18:8b:ed:43:15:4a:54:bf:23:af:ba" or pe.signatures[i].serial=="00:ad:0a:95:8c:df:18:8b:ed:43:15:4a:54:bf:23:af:ba"))
}
