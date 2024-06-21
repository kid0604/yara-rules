rule Kimsuky_InfoKey_ps1
{
	meta:
		description = "Powershell file with keylogger functionality used by Kimsuky"
		author = "JPCERT/CC Incident Response Group"
		hash = "cc2355edb2e2888bae37925ec3ddce2c4c7a91973e89ee385074c337107175ca"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "Global\\AlreadyRunning19122345" ascii
		$s2 = "if(($upTick -eq 0) -or (($curTick - $upTick) -gt $tickGap)){" ascii
		$s3 = "`n----- [Clipboard] -----`n\" + [Windows.Clipboard]::GetText()"
		$s4 = "`n----- [\" + $t + \"] [\" + $curWnd.ToString() + \"] -----`n"

	condition:
		3 of them
}
