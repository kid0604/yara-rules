rule p0wnedListenerConsole
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedListenerConsole.cs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		date = "2017-01-14"
		hash1 = "d2d84e65fad966a8556696fdaab5dc8110fc058c9e9caa7ea78aa00921ae3169"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "Invoke_ReflectivePEInjection" fullword wide
		$x5 = "p0wnedShell> " fullword wide
		$x6 = "Resources.Get_PassHashes" fullword wide
		$s7 = "Invoke_CredentialsPhish" fullword wide
		$s8 = "Invoke_Shellcode" fullword wide
		$s9 = "Resources.Invoke_TokenManipulation" fullword wide
		$s10 = "Resources.Port_Scan" fullword wide
		$s20 = "Invoke_PowerUp" fullword wide

	condition:
		1 of them
}
