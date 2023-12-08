import "pe"

rule MAL_Unknown_PWDumper_Apr18_3
{
	meta:
		description = "Detects sample from unknown sample set - IL origin"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-04-06"
		hash1 = "d435e7b6f040a186efeadb87dd6d9a14e038921dc8b8658026a90ae94b4c8b05"
		hash2 = "8c35c71838f34f7f7a40bf06e1d2e14d58d9106e6d4e6f6e9af732511a126276"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "loaderx86.dll" fullword ascii
		$s2 = "tcpsvcs.exe" fullword wide
		$s3 = "%Program Files, Common FOLDER%" fullword wide
		$s4 = "%AllUsers, ApplicationData FOLDER%" fullword wide
		$s5 = "loaderx86" fullword ascii
		$s6 = "TNtDllHook$" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and all of them
}
