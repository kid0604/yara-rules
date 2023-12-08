rule CN_Honker_Webshell_assembly
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file assembly.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "2bcb4d22758b20df6b9135d3fb3c8f35a9d9028e"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "response.write oScriptlhn.exec(\"cmd.exe /c\" & request(\"c\")).stdout.readall" fullword ascii

	condition:
		filesize <1KB and all of them
}
