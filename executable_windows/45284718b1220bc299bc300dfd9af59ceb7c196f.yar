rule malware_windows_apt_red_leaves_generic
{
	meta:
		description = "Red Leaves malware, related to APT10"
		reference = "https://github.com/nccgroup/Cyber-Defence/blob/master/Technical%20Notes/Red%20Leaves/Source/Red%20Leaves%20technical%20note%20v1.0.md"
		author = "David Cannings"
		md5 = "81df89d6fa0b26cadd4e50ef5350f341"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "Feb 04 2015"
		$a2 = "I can not start %s"
		$a3 = "dwConnectPort" fullword
		$a4 = "dwRemoteLanPort" fullword
		$a5 = "strRemoteLanAddress" fullword
		$a6 = "strLocalConnectIp" fullword
		$a7 = "\\\\.\\pipe\\NamePipe_MoreWindows" wide
		$a8 = "RedLeavesCMDSimulatorMutex" wide
		$a9 = "(NT %d.%d Build %d)" wide
		$a10 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E)" wide
		$a11 = "red_autumnal_leaves_dllmain.dll" wide ascii
		$a12 = "__data" wide
		$a13 = "__serial" wide
		$a14 = "__upt" wide
		$a15 = "__msgid" wide

	condition:
		7 of ($a*)
}
