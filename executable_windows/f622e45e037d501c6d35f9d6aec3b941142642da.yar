import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_RDP
{
	meta:
		author = "ditekSHen"
		description = "Detects executables embedding registry key / value combination manipulating RDP / Terminal Services"
		os = "windows"
		filetype = "executable"

	strings:
		$r1 = "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" ascii wide nocase
		$k1 = "EnableAdminTSRemote" fullword ascii wide nocase
		$r2 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" ascii wide nocase
		$k2 = "TSEnabled" fullword ascii wide nocase
		$r3 = "SYSTEM\\CurrentControlSet\\Services\\TermDD" ascii wide nocase
		$r4 = "SYSTEM\\CurrentControlSet\\Services\\TermService" ascii wide nocase
		$k3 = "Start" fullword ascii wide nocase
		$r5 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" ascii wide nocase
		$k4 = "fDenyTSConnections" fullword ascii wide nocase
		$r6 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\RDPTcp" ascii wide nocase
		$r7 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd\\Tds\\tcp" ascii wide nocase
		$r8 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" ascii wide nocase
		$k5 = "PortNumber" fullword ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 5 of ($r*) and 3 of ($k*)
}
