rule WinPayloads_PowerShell
{
	meta:
		description = "Detects WinPayloads PowerShell Payload"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nccgroup/Winpayloads"
		date = "2017-07-11"
		hash1 = "011eba8f18b66634f6eb47527b4ceddac2ae615d6861f89a35dbb9fc591cae8e"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "$Base64Cert = 'MIIJeQIBAzCCCT8GCSqGSIb3DQEHAaCCCTAEggksMIIJKDCCA98GCSqGSIb3DQEHBqCCA9AwggPMAgEAMIIDxQYJKoZIhvcNAQcBMBwGCiqGSIb3D" ascii
		$x2 = "powershell -w hidden -noni -enc SQBF" fullword ascii nocase
		$x3 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwA" ascii
		$x4 = "powershell.exe -WindowStyle Hidden -enc JABjAGwAaQBlAG4AdAA" ascii

	condition:
		filesize <10KB and 1 of them
}
