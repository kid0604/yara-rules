rule Empire_Get_Keystrokes
{
	meta:
		description = "Detects Empire component - file Get-Keystrokes.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		hash1 = "c36e71db39f6852f78df1fa3f67e8c8a188bf951e96500911e9907ee895bf8ad"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "$RightMouse   = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::RButton) -band 0x8000) -eq 0x8000" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <30KB and 1 of them ) or all of them
}
