rule IronPanda_Webshell_JSP
{
	meta:
		description = "Iron Panda Malware JSP"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/E4qia9"
		date = "2015-09-16"
		hash = "3be95477e1d9f3877b4355cff3fbcdd3589bb7f6349fd4ba6451e1e9d32b7fa6"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "Bin_ExecSql(\"exec master..xp_cmdshell'bcp \\\"select safile from \" + db + \"..bin_temp\\\" queryout \\\"\" + Bin_TextBox_SaveP" ascii
		$s2 = "tc.Text=\"<a href=\\\"javascript:Bin_PostBack('zcg_ClosePM','\"+Bin_ToBase64(de.Key.ToString())+\"')\\\">Close</a>\";" fullword ascii
		$s3 = "Bin_ExecSql(\"IF OBJECT_ID('bin_temp')IS NOT NULL DROP TABLE bin_temp\");" fullword ascii

	condition:
		filesize <330KB and 1 of them
}
