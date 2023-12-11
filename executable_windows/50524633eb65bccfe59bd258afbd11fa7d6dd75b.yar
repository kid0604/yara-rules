rule network_toredo
{
	meta:
		author = "x0r"
		description = "Communications over Toredo network"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$f1 = "FirewallAPI.dll" nocase
		$p1 = "\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\" nocase

	condition:
		all of them
}
