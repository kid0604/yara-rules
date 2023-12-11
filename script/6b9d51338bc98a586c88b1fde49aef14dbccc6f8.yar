rule webshell_customize
{
	meta:
		description = "Web Shell - file customize.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "d55578eccad090f30f5d735b8ec530b1"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"

	condition:
		all of them
}
