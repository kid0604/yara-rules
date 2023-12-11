rule asp_shell : webshell
{
	meta:
		description = "Laudanum Injector Tools - file shell.asp"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "8bf1ff6f8edd45e3102be5f8a1fe030752f45613"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "<form action=\"shell.asp\" method=\"POST\" name=\"shell\">" fullword ascii
		$s2 = "%ComSpec% /c dir" fullword ascii
		$s3 = "Set objCmd = wShell.Exec(cmd)" fullword ascii
		$s4 = "Server.ScriptTimeout = 180" fullword ascii
		$s5 = "cmd = Request.Form(\"cmd\")" fullword ascii
		$s6 = "' ***  http://laudanum.secureideas.net" fullword ascii
		$s7 = "Dim wshell, intReturn, strPResult" fullword ascii

	condition:
		filesize <15KB and 4 of them
}
