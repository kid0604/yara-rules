import "pe"

rule INDICATOR_KB_CERT_0e96837dbe5f4548547203919b96ac27
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "d6c6a0a4a57af645c9cad90b57c696ad9ad9fcf9"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PLAN CORP PTY LTD" and pe.signatures[i].serial=="0e:96:83:7d:be:5f:45:48:54:72:03:91:9b:96:ac:27")
}
