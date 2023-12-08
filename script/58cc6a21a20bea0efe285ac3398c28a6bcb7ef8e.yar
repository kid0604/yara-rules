import "pe"

rule TA17_293A_Hacktool_Exploit_MS16_032
{
	meta:
		description = "Auto-generated rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		date = "2017-10-21"
		hash1 = "9b97290300abb68fb48480718e6318ee2cdd4f099aa6438010fb2f44803e0b58"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "[?] Thread belongs to: $($(Get-Process -PID $([Kernel32]::GetProcessIdOfThread($Thread)))" ascii
		$x2 = "0x00000002, \"C:\\Windows\\System32\\cmd.exe\", \"\"," fullword ascii
		$x3 = "PowerShell implementation of MS16-032. The exploit targets all vulnerable" fullword ascii
		$x4 = "If we can't open the process token it's a SYSTEM shell!" fullword ascii

	condition:
		( filesize <40KB and 1 of them )
}
