import "pe"

rule INDICATOR_KB_CERT_040cc2255db4e48da1b4f242f5edfa73
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "1270a79829806834146ef50a8036cfcc1067e0822e400f81073413a60aa9ed54"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Softland SRL" and pe.signatures[i].serial=="04:0c:c2:25:5d:b4:e4:8d:a1:b4:f2:42:f5:ed:fa:73")
}
