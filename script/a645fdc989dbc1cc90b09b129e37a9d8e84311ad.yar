rule webshell_ASP_aspydrv
{
	meta:
		description = "Web Shell - file aspydrv.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "de0a58f7d1e200d0b2c801a94ebce330"
		os = "windows"
		filetype = "script"

	strings:
		$s3 = "<%=thingy.DriveLetter%> </td><td><tt> <%=thingy.DriveType%> </td><td><tt> <%=thi"

	condition:
		all of them
}
