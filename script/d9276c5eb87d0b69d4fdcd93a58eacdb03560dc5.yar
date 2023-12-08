rule webshell_jsp_utils
{
	meta:
		description = "Web Shell - file utils.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "9827ba2e8329075358b8e8a53e20d545"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "ResultSet r = c.getMetaData().getTables(null, null, \"%\", t);" fullword
		$s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"

	condition:
		all of them
}
