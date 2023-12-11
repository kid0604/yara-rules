import "pe"

rule INDICATOR_KB_CERT_22367dbefd0a325c3893af52547b14fa
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "b5cb5b256e47a30504392c37991e4efc4ce838fde4ad8df47456d30b417e6d5c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "F.lux Software LLC" and pe.signatures[i].serial=="22:36:7d:be:fd:0a:32:5c:38:93:af:52:54:7b:14:fa")
}
