rule Win_PrivEsc_folderperm
{
	meta:
		description = "Detects a tool that can be used for privilege escalation - file folderperm.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.greyhathacker.net/?p=738"
		date = "2016-06-02"
		score = 80
		hash1 = "1aa87df34826b1081c40bb4b702750587b32d717ea6df3c29715eb7fc04db755"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "# powershell.exe -executionpolicy bypass -file folderperm.ps1" fullword ascii
		$x2 = "Write-Host \"[i] Dummy test file used to test access was not outputted:\" $filetocopy" fullword ascii
		$x3 = "Write-Host -foregroundColor Red \"      Access denied :\" $myarray[$i] " fullword ascii

	condition:
		1 of them
}
