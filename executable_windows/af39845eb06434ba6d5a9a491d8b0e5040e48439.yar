import "pe"

rule INDICATOR_KB_CERT_2925263b65c7fe1cd47b0851cc6951e3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "88ef10f0e160b1b4bb8f0777a012f6b30ac88ac8"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "tuning buddy limited" and pe.signatures[i].serial=="29:25:26:3b:65:c7:fe:1c:d4:7b:08:51:cc:69:51:e3")
}
