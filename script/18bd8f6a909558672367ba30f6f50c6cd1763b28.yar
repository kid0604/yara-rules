rule CN_Honker_Webshell_cfm_list
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file list.cfm"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "85d445b13d2aef1df3b264c9b66d73f0ff345cec"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s1 = "<TD><a href=\"javascript:ShowFile('#mydirectory.name#')\">#mydirectory.name#</a>" ascii
		$s2 = "<TD>#mydirectory.size#</TD>" fullword ascii

	condition:
		filesize <10KB and all of them
}
