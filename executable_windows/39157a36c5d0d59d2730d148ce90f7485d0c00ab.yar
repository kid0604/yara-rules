import "pe"

rule INDICATOR_KB_CERT_00ee663737d82df09c7038a6a6693a8323
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "dc934afe82adbab8583e393568f81ab32c79aeea"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KREACIJA d.o.o." and pe.signatures[i].serial=="00:ee:66:37:37:d8:2d:f0:9c:70:38:a6:a6:69:3a:83:23")
}
