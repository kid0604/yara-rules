import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_References_VPN
{
	meta:
		author = "ditekSHen"
		description = "Detects executables referencing many VPN software clients. Observed in infosteslers"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\VPN\\NordVPN" ascii wide nocase
		$s2 = "\\VPN\\OpenVPN" ascii wide nocase
		$s3 = "\\VPN\\ProtonVPN" ascii wide nocase
		$s4 = "\\VPN\\DUC\\" ascii wide nocase
		$s5 = "\\VPN\\PrivateVPN" ascii wide nocase
		$s6 = "\\VPN\\PrivateVPN" ascii wide nocase
		$s7 = "\\VPN\\EarthVPN" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 3 of them
}
