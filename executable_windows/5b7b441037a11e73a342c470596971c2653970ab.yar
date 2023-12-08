import "pe"

rule INDICATOR_KB_CERT_00818631110b5d14331dac7e6ad998b902
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c93082334ef8c2d6a0a1823cdf632c0d75d56377"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "2 TOY GUYS LLC" and (pe.signatures[i].serial=="00:81:86:31:11:0b:5d:14:33:1d:ac:7e:6a:d9:98:b9:02" or pe.signatures[i].serial=="81:86:31:11:0b:5d:14:33:1d:ac:7e:6a:d9:98:b9:02"))
}
