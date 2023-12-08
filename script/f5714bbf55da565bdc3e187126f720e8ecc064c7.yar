rule Hacktools_CN_Burst_Clear
{
	meta:
		description = "Disclosed hacktool set - file Clear.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "148c574a4e6e661aeadaf3a4c9eafa92a00b68e4"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "del /f /s /q %systemdrive%\\*.log    " fullword ascii
		$s1 = "del /f /s /q %windir%\\*.bak    " fullword ascii
		$s4 = "del /f /s /q %systemdrive%\\*.chk    " fullword ascii
		$s5 = "del /f /s /q %systemdrive%\\*.tmp    " fullword ascii
		$s8 = "del /f /q %userprofile%\\COOKIES s\\*.*    " fullword ascii
		$s9 = "rd /s /q %windir%\\temp & md %windir%\\temp    " fullword ascii
		$s11 = "del /f /s /q %systemdrive%\\recycled\\*.*    " fullword ascii
		$s12 = "del /f /s /q \"%userprofile%\\Local Settings\\Temp\\*.*\"    " fullword ascii
		$s19 = "del /f /s /q \"%userprofile%\\Local Settings\\Temporary Internet Files\\*.*\"   " ascii

	condition:
		5 of them
}
