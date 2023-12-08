rule System_Tools
{
	meta:
		description = "Contains references to system / monitoring tools"
		author = "Ivan Kwiatkowski (@JusticeRage)"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = "wireshark.exe" nocase wide ascii
		$a1 = "ethereal.exe" nocase wide ascii
		$a2 = "netstat.exe" nocase wide ascii
		$a3 = /taskm(an|gr|on).exe/ nocase wide ascii
		$a4 = /regedit(32)?.exe/ nocase wide ascii
		$a5 = "sc.exe" nocase wide ascii
		$a6 = "procexp.exe" nocase wide ascii
		$a7 = "procmon.exe" nocase wide ascii
		$a8 = "netmon.exe" nocase wide ascii
		$a9 = "regmon.exe" nocase wide ascii
		$a10 = "filemon.exe" nocase wide ascii
		$a11 = "msconfig.exe" nocase wide ascii
		$a12 = "vssadmin.exe" nocase wide ascii
		$a13 = "bcdedit.exe" nocase wide ascii
		$a14 = "dumpcap.exe" nocase wide ascii
		$a15 = "tcpdump.exe" nocase wide ascii
		$a16 = "mshta.exe" nocase wide ascii
		$a17 = "control.exe" nocase wide ascii
		$a18 = "regsvr32.exe" nocase wide ascii
		$a19 = "rundll32.exe" nocase wide ascii

	condition:
		any of them
}
