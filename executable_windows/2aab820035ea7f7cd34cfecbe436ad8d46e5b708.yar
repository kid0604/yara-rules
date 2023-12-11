rule rat_rdp
{
	meta:
		author = "x0r"
		description = "Remote Administration toolkit enable RDP"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$p1 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" nocase
		$p2 = "software\\microsoft\\windows nt\\currentversion\\terminal server" nocase
		$p3 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" nocase
		$r1 = "EnableAdminTSRemote"
		$c1 = "net start termservice"
		$c2 = "sc config termservice start"

	condition:
		any of them
}
