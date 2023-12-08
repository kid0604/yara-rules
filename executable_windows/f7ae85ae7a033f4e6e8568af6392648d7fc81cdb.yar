import "pe"

rule MALWARE_Win_CHUWI_Seth
{
	meta:
		author = "ditekSHen"
		description = "Detects detected unknown RAT. Called CHUWI based on PDB, and promoted to Seth Ransomware."
		snort2_sid = "920103-920105"
		snort3_sid = "920101-920103"
		notes = "First sighting on 2020-01-05 didn't include ransomware artificats. Second sighting on 2020-01-24 with several correlations between the two samples now include ransomware artifacts."
		os = "windows"
		filetype = "executable"

	strings:
		$cmd1 = "shell_command" fullword ascii
		$cmd2 = "check_command" fullword ascii
		$cmd3 = "down_exec" fullword ascii
		$cmd4 = "open_link" fullword ascii
		$cmd5 = "down_exec" fullword ascii
		$cmd6 = "exe_link" fullword ascii
		$cmd7 = "shellCommand" fullword ascii
		$cmd8 = "R_CMMAND" fullword ascii
		$cnc1 = "/check_command.php?HWID=" ascii
		$cnc2 = "&act=get_command" ascii
		$cnc3 = "/get_command.php?hwid=" ascii
		$cnc4 = "&command=down_exec" ascii
		$cnc5 = "&command=message" ascii
		$cnc6 = "&command=open_link" ascii
		$cnc7 = "&command=down_exec" ascii
		$cnc8 = "&command=shell" ascii
		$pdb = "\\Users\\CHUWI\\Documents\\CPROJ\\Downloader\\svchost" ascii
		$rcnc1 = "inc/check_command.php" ascii
		$rcnc2 = "inc/get_command.php" ascii
		$rcnc3 = "php?btc" ascii
		$rcnc4 = "php?hwid" ascii
		$x1 = "> %USERPROFILE%\\Desktop\\HOW_DECRYPT_FILES.seth.txt" ascii
		$x2 = "/C dir /b %USERPROFILE%\\Documents > %temp%\\doc.txt" ascii
		$x3 = "/C dir /b %USERPROFILE%\\Desktop > %temp%\\desk.txt" ascii
		$x4 = "/C dir /b %USERPROFILE%\\Downloads > %temp%\\downs.txt" ascii
		$x5 = "/C dir /b %USERPROFILE%\\Pictures > %temp%\\pics.txt" ascii
		$x6 = "for /F \"delims=\" %%a in ('mshta.exe \"%~F0\"') do set \"HTA=%%a\"" ascii
		$x7 = "\\svchost.exe" fullword ascii
		$x8 = ".seth" fullword ascii
		$x9 = "MyAgent" fullword ascii

	condition:
		uint16(0)==0x5a4d and ($pdb or 5 of ($cmd*) or 4 of ($cnc*) or all of ($rcnc*) or 5 of ($x*) or 8 of them )
}
