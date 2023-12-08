rule ps1_toolkit_Inveigh_BruteForce_2
{
	meta:
		description = "Auto-generated rule - from files Inveigh-BruteForce.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "}.NTLMv2_file_queue[0]|Out-File ${" ascii
		$s2 = "}.NTLMv2_file_queue.RemoveRange(0,1)" ascii
		$s3 = "}.NTLMv2_file_queue.Count -gt 0)" ascii
		$s4 = "}.relay_running = $false" ascii

	condition:
		( uint16(0)==0xbbef and filesize <200KB and 2 of them ) or (4 of them )
}
