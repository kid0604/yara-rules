rule APT30_Sample_11
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "59066d5d1ee3ad918111ed6fcaf8513537ff49a6"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "System\\CurrentControlSet\\control\\ComputerName\\ComputerName" fullword ascii
		$s1 = "msofscan.exe" fullword wide
		$s2 = "Mozilla/4.0 (compatible; MSIE 5.0; Win32)" fullword ascii
		$s3 = "Microsoft? is a registered trademark of Microsoft Corporation." fullword wide
		$s4 = "Windows XP Professional x64 Edition or Windows Server 2003" fullword ascii
		$s9 = "NetEagle_Scout - " fullword ascii
		$s10 = "Server 4.0, Enterprise Edition" fullword ascii
		$s11 = "Windows 3.1(Win32s)" fullword ascii
		$s12 = "%s%s%s %s" fullword ascii
		$s13 = "Server 4.0" fullword ascii
		$s15 = "Windows Millennium Edition" fullword ascii
		$s16 = "msofscan" fullword wide
		$s17 = "Eagle-Norton360-OfficeScan" fullword ascii
		$s18 = "Workstation 4.0" fullword ascii
		$s19 = "2003 Microsoft Office system" fullword wide

	condition:
		filesize <250KB and uint16(0)==0x5A4D and all of them
}
