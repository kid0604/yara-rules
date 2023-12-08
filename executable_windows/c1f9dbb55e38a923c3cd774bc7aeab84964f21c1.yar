import "pe"

rule INDICATOR_KB_CERT_2e8023a5a0328f66656e1fc251c82680
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e3eff064ad23cc4c98cdbcd78e4e5a69527cf2e4"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Philippe Mantes" and pe.signatures[i].serial=="2e:80:23:a5:a0:32:8f:66:65:6e:1f:c2:51:c8:26:80")
}
