import "pe"

rule INDICATOR_KB_CERT_00df7139e106dbb68dfe4de97d862af708
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4ac627227a25f0914f3a73ff85d90b45da589329"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "zPfPJHDCzusZRYQYJZGZoFfZmvYtSlFXDPQKtoQzc" and pe.signatures[i].serial=="00:df:71:39:e1:06:db:b6:8d:fe:4d:e9:7d:86:2a:f7:08")
}
