rule Invoke_SMBExec_Invoke_WMIExec_1
{
	meta:
		description = "Auto-generated rule - from files Invoke-SMBExec.ps1, Invoke-WMIExec.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Kevin-Robertson/Invoke-TheHash"
		date = "2017-06-14"
		super_rule = 1
		hash1 = "674fc045dc198874f323ebdfb9e9ff2f591076fa6fac8d1048b5b8d9527c64cd"
		hash2 = "b41bd54bbf119d153e0878696cd5a944cbd4316c781dd8e390507b2ec2d949e7"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "$process_ID = $process_ID -replace \"-00-00\",\"\"" fullword ascii
		$s2 = "Write-Output \"$Target did not respond\"" fullword ascii
		$s3 = "[Byte[]]$packet_call_ID_bytes = [System.BitConverter]::GetBytes($packet_call_ID)" fullword ascii

	condition:
		all of them
}
