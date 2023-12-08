rule CN_Honker_Alien_D
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file D.ASP"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "de9cd4bd72b1384b182d58621f51815a77a5f07d"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "Paths_str=\"c:\\windows\\\"&chr(13)&chr(10)&\"c:\\Documents and Settings\\\"&chr" ascii
		$s1 = "CONST_FSO=\"Script\"&\"ing.Fil\"&\"eSyst\"&\"emObject\"" fullword ascii
		$s2 = "Response.Write \"<form id='form1' name='form1' method='post' action=''>\"" fullword ascii
		$s3 = "set getAtt=FSO.GetFile(filepath)" fullword ascii
		$s4 = "Response.Write \"<input name='NoCheckTemp' type='checkbox' id='NoCheckTemp' chec" ascii

	condition:
		filesize <30KB and 2 of them
}
