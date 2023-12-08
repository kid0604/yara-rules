import "pe"

rule INDICATOR_KB_CERT_c7e62986c36246c64b8c9f2348141570
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "f779e06266802b395ef6d3dbfeb1cc6a0a2cfc47"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LLC Mail.Ru" and pe.signatures[i].serial=="c7:e6:29:86:c3:62:46:c6:4b:8c:9f:23:48:14:15:70")
}
