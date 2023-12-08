import "pe"

rule INDICATOR_KB_CERT_00881573fc67ff7395dde5bccfbce5b088
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "31b3a3c173c2a2d1086794bfc8d853e25e62fb46"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Trade in Brasil s.r.o." and (pe.signatures[i].serial=="88:15:73:fc:67:ff:73:95:dd:e5:bc:cf:bc:e5:b0:88" or pe.signatures[i].serial=="00:88:15:73:fc:67:ff:73:95:dd:e5:bc:cf:bc:e5:b0:88"))
}
