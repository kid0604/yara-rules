import "pe"

rule INDICATOR_KB_CERT_Podangers
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "6e757c3b91d75d58b5230c27a2fcc01bfe5fe60f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PODANGERS" and pe.signatures[i].serial=="00")
}
