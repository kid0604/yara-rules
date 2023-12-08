rule CN_Honker_ChinaChopper
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ChinaChopper.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "fa347fdb23ab0b8d0560a0d20c434549d78e99b5"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "$m=get_magic_quotes_gpc();$sid=$m?stripslashes($_POST[\"z1\"]):$_POST[\"z1\"];$u" wide
		$s3 = "SETP c:\\windows\\system32\\cmd.exe " fullword wide
		$s4 = "Ev al (\"Exe cute(\"\"On+Error+Resume+Next:%s:Response.Write(\"\"\"\"->|\"\"\"\"" wide

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 1 of them
}
