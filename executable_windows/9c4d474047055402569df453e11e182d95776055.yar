import "pe"

rule INDICATOR_KB_CERT_0086909b91f07f9316984d888d1e28ab76
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "5eba3c38e989c7d16c987e2989688d3bd24032bc"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dantherm Intelligent Monitoring A/S" and pe.signatures[i].serial=="00:86:90:9b:91:f0:7f:93:16:98:4d:88:8d:1e:28:ab:76")
}
