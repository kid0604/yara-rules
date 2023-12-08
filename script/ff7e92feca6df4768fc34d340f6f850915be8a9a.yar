rule Obfuscated_VBS_April17
{
	meta:
		description = "Detects cloaked Mimikatz in VBS obfuscation"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-04-21"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "::::::ExecuteGlobal unescape(unescape(" ascii

	condition:
		filesize <500KB and all of them
}
