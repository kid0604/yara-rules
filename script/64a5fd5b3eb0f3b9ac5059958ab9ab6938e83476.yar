rule APT_UNC2447_BAT_Runner_May21_1
{
	meta:
		description = "Detects Batch script runners from UNC2447 campaign"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
		date = "2021-05-01"
		modified = "2023-01-07"
		hash1 = "ccacf4658ae778d02e4e55cd161b5a0772eb8b8eee62fed34e2d8f11db2cc4bc"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "powershell.exe -c \"[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String([IO.File]::" ascii
		$x2 = "wwansvc.txt')))\" | powershell.exe -" ascii

	condition:
		filesize <5000KB and 1 of them
}
