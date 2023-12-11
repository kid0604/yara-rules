rule CN_Honker_Havij_Havij
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Havij.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0d8b275bd1856bc6563dd731956f3b312e1533cd"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "User-Agent: %Inject_Here%" fullword wide
		$s2 = "BACKUP database master to disk='d:\\Inetpub\\wwwroot\\1.zip'" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and all of them
}
