rule CN_Honker_NBSI_3_0
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file NBSI 3.0.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "93bf0f64bec926e9aa2caf4c28df9af27ec0e104"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = ";use master declare @o int exec sp_oacreate 'wscript.shell',@o out exec sp_oamet" wide
		$s2 = "http://localhost/1.asp?id=16" fullword ascii
		$s3 = " exec master.dbo.xp_cmdshell @Z--" fullword wide
		$s4 = ";use master declare @o int exec sp_oacreate 'wscript.shell',@o out exec sp_oamet" wide

	condition:
		uint16(0)==0x5a4d and filesize <2600KB and 2 of them
}
