rule INDICATOR_TOOL_PWS_SniffPass
{
	meta:
		author = "ditekSHen"
		description = "Detects SniffPass, a password monitoring software that listens on the network and captures passwords over POP3, IMAP4, SMTP, FTP, and HTTP."
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Release\\SniffPass.pdb" ascii
		$s2 = "Password   Sniffer" fullword wide
		$s3 = "Software\\NirSoft\\SniffPass" fullword ascii
		$s4 = "Sniffed PasswordsCFailed to start" wide
		$s5 = "Pwpcap.dll" fullword ascii
		$s6 = "nmwifi.exe" fullword ascii
		$s7 = "NmApi.dll" fullword ascii
		$s8 = "npptools.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}
