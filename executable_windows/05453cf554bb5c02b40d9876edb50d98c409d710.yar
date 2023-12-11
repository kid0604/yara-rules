rule APT_NK_AR18_165A_1
{
	meta:
		description = "Detects APT malware from AR18-165A report by US CERT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR18-165A"
		date = "2018-06-15"
		hash1 = "089e49de61701004a5eff6de65476ed9c7632b6020c2c0f38bb5761bca897359"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "netsh.exe advfirewall firewall add rule name=\"PortOpenning\" dir=in protocol=tcp localport=%d action=allow enable=yes" fullword wide
		$s2 = "netsh.exe firewall add portopening TCP %d \"PortOpenning\" enable" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 1 of them
}
