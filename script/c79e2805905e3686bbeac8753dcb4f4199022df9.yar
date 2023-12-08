rule CN_Honker_Webshell_ASP_asp1
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file asp1.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "78b5889b363043ed8a60bed939744b4b19503552"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "SItEuRl=" ascii
		$s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
		$s3 = "Server.ScriptTimeout=" ascii

	condition:
		filesize <200KB and all of them
}
