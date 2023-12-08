rule ps1_toolkit_Invoke_Mimikatz_RelfectivePEInjection
{
	meta:
		description = "Auto-generated rule - from files Invoke-Mimikatz.ps1, Invoke-RelfectivePEInjection.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		super_rule = 1
		hash1 = "5c31a2e3887662467cfcb0ac37e681f1d9b0f135e6dfff010aae26587e03d8c8"
		hash2 = "510b345f821f93c1df5f90ac89ad91fcd0f287ebdabec6c662b716ec9fddb03a"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "[IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])" fullword ascii
		$s2 = "if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)" fullword ascii
		$s3 = "[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)" fullword ascii
		$s4 = "Function Import-DllInRemoteProcess" fullword ascii
		$s5 = "FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))" fullword ascii
		$s6 = "[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)" fullword ascii
		$s7 = "[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)" fullword ascii
		$s8 = "[System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null" fullword ascii
		$s9 = "::FromBase64String('RABvAG4AZQAhAA==')))" ascii
		$s10 = "Write-Verbose \"PowerShell ProcessID: $PID\"" fullword ascii
		$s11 = "[IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])" fullword ascii

	condition:
		( uint16(0)==0xbbef and filesize <10000KB and 3 of them ) or (6 of them )
}
