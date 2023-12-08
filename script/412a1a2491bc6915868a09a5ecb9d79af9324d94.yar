rule Empire_Invoke_Portscan_Gen
{
	meta:
		description = "Detects Empire component - from files Invoke-Portscan.ps1, Invoke-Portscan.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		super_rule = 1
		hash2 = "cf7030be01fab47e79e4afc9e0d4857479b06a5f68654717f3bc1bc67a0f38d3"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "Test-Port -h $h -p $Port -timeout $Timeout" fullword ascii
		$s2 = "1 {$nHosts=10;  $Threads = 32;   $Timeout = 5000 }" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <100KB and 1 of them ) or all of them
}
