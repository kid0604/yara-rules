rule Empire_portscan
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file portscan.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "b355efa1e7b3681b1402e22c58ce968795ef245fd08a0afb948d45c173e60b97"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "script += \"Invoke-PortScan -noProgressMeter -f\"" fullword ascii
		$s2 = "script += \" | ? {$_.alive}| Select-Object HostName,@{name='OpenPorts';expression={$_.openPorts -join ','}} | ft -wrap | Out-Str" ascii

	condition:
		filesize <14KB and all of them
}
