rule hacktool_macos_exploit_cve_5889
{
	meta:
		description = "http://www.cvedetails.com/cve/cve-2015-5889"
		reference = "https://www.exploit-db.com/exploits/38371/"
		author = "@mimeframe"
		os = "macos"
		filetype = "script"

	strings:
		$a1 = "/etc/sudoers" fullword wide ascii
		$a2 = "/etc/crontab" fullword wide ascii
		$a3 = "* * * * * root echo" wide ascii
		$a4 = "ALL ALL=(ALL) NOPASSWD: ALL" wide ascii
		$a5 = "/usr/bin/rsh" fullword wide ascii
		$a6 = "localhost" fullword wide ascii

	condition:
		all of ($a*)
}
