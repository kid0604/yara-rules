rule malware_windows_remcos_rat
{
	meta:
		description = "https://blog.fortinet.com/2017/02/14/remcos-a-new-rat-in-the-wild-2"
		reference = "https://breaking-security.net/remcos/remcos-changelog/"
		author = "@mimeframe"
		md5 = "c8dafe143fe1d81ae6a3c0cd4724b272"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "[Following text has been pasted from clipboard:]" wide ascii
		$a2 = "[Chrome StoredLogins found, cleared!]" wide ascii
		$a3 = "[Firefox StoredLogins cleared!]" wide ascii
		$b1 = "getclipboard" wide ascii
		$b2 = "stopmiccapture" wide ascii
		$b3 = "downloadfromurltofile" wide ascii
		$b4 = "getcamsingleframe" wide ascii
		$c1 = "Breaking-Security.Net" wide ascii
		$c2 = "REMCOS v" wide ascii

	condition:
		any of ($a*) or 3 of ($b*) or all of ($c*)
}
