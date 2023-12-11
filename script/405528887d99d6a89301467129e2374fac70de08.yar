rule CN_Honker_sig_3389_3389_2
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file 3389.bat"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "5ff92f39ade12f8ba6cb75dfdc9bb907e49f0ebd"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "@del c:\\termsrvhack.dll" fullword ascii
		$s2 = "@del c:\\3389.txt" fullword ascii

	condition:
		filesize <3KB and all of them
}
