rule webshell_jsp_IXRbE
{
	meta:
		description = "Web Shell - file IXRbE.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "e26e7e0ebc6e7662e1123452a939e2cd"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application"

	condition:
		all of them
}
