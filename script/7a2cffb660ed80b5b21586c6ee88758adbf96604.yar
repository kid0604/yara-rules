rule aspx_shell : webshell
{
	meta:
		description = "Laudanum Injector Tools - file shell.aspx"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "076aa781a004ecb2bf545357fd36dcbafdd68b1a"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "remoteIp = HttpContext.Current.Request.Headers[\"X-Forwarded-For\"].Split(new" ascii
		$s2 = "remoteIp = Request.UserHostAddress;" fullword ascii
		$s3 = "<form method=\"post\" name=\"shell\">" fullword ascii
		$s4 = "<body onload=\"document.shell.c.focus()\">" fullword ascii

	condition:
		filesize <20KB and all of them
}
