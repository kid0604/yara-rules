rule CN_Honker_Webshell_ASP_asp2
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file asp2.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b3ac478e72a0457798a3532f6799adeaf4a7fc87"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "<%=server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii
		$s2 = "webshell</font> <font color=#00FF00>" fullword ascii
		$s3 = "Userpwd = \"admin\"   'User Password" fullword ascii

	condition:
		filesize <10KB and all of them
}
