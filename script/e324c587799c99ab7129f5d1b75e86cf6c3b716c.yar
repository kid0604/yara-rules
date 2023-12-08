rule ps1_toolkit_Inveigh_BruteForce
{
	meta:
		description = "Auto-generated rule - file Inveigh-BruteForce.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "Import-Module .\\Inveigh.psd1;Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 " fullword ascii
		$s2 = "$(Get-Date -format 's') - Attempting to stop HTTP listener\")|Out-Null" fullword ascii
		$s3 = "Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 -Hostname server1" fullword ascii

	condition:
		( uint16(0)==0xbbef and filesize <300KB and 1 of them ) or (2 of them )
}
