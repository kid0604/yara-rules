rule Hacktool_Strings_p0wnedShell : FILE
{
	meta:
		description = "Detects strings found in Runspace Post Exploitation Toolkit"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		date = "2017-01-14"
		modified = "2023-02-10"
		hash1 = "e1f35310192416cd79e60dba0521fc6eb107f3e65741c344832c46e9b4085e60"
		nodeepdive = 1
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "Invoke-TokenManipulation" fullword ascii
		$x2 = "windows/meterpreter" fullword ascii
		$x3 = "lsadump::dcsync" fullword ascii
		$x4 = "p0wnedShellx86" fullword ascii
		$x5 = "p0wnedShellx64" fullword ascii
		$x6 = "Invoke_PsExec()" fullword ascii
		$x7 = "Invoke-Mimikatz" fullword ascii
		$x8 = "Invoke_Shellcode()" fullword ascii
		$x9 = "Invoke-ReflectivePEInjection" ascii
		$fp1 = "Sentinel Labs, Inc." wide
		$fp2 = "Copyright Elasticsearch B.V." ascii wide
		$fp3 = "Attack Information: Invoke-Mimikatz" ascii
		$fp4 = "a30226 || INDICATOR-SHELLCODE Metasploit windows/meterpreter stage transfer attempt"
		$fp5 = "use strict"

	condition:
		filesize <20MB and 1 of ($x*) and not 1 of ($fp*)
}
