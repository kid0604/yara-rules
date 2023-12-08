rule Msfpayloads_msf_exe
{
	meta:
		description = "Metasploit Payloads - file msf-exe.vba"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "321537007ea5052a43ffa46a6976075cee6a4902af0c98b9fd711b9f572c20fd"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "'* PAYLOAD DATA" fullword ascii
		$s2 = " = Shell(" ascii
		$s3 = "= Environ(\"USERPROFILE\")" fullword ascii
		$s4 = "'**************************************************************" fullword ascii
		$s5 = "ChDir (" ascii
		$s6 = "'* MACRO CODE" fullword ascii

	condition:
		4 of them
}
