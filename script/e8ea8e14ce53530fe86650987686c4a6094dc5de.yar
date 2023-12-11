rule Msfpayloads_msf_2
{
	meta:
		description = "Metasploit Payloads - file msf.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "e52f98466b92ee9629d564453af6f27bd3645e00a9e2da518f5a64a33ccf8eb5"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "& \"\\\" & \"svchost.exe\"" fullword ascii
		$s2 = "CreateObject(\"Wscript.Shell\")" fullword ascii
		$s3 = "<% @language=\"VBScript\" %>" fullword ascii

	condition:
		all of them
}
