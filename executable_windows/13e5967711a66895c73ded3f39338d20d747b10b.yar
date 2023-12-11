import "pe"

rule INDICATOR_KB_CERT_030012f134e64347669f3256c7d050c5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "959caa354b28892608ab1bb9519424c30bebc155"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Futumarket LLC" and pe.signatures[i].serial=="03:00:12:f1:34:e6:43:47:66:9f:32:56:c7:d0:50:c5")
}
