rule Msfpayloads_msf_11
{
	meta:
		description = "Metasploit Payloads - file msf.hta"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "d1daf7bc41580322333a893133d103f7d67f5cd8a3e0f919471061d41cf710b6"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = ".ExpandEnvironmentStrings(\"%PSModulePath%\") + \"..\\powershell.exe\") Then" fullword ascii
		$s2 = "= CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
		$s3 = "= CreateObject(\"Wscript.Shell\") " fullword ascii

	condition:
		all of them
}
