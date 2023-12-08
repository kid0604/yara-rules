rule asp_dns : webshell
{
	meta:
		description = "Laudanum Injector Tools - file dns.asp"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "5532154dd67800d33dace01103e9b2c4f3d01d51"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "command = \"nslookup -type=\" & qtype & \" \" & query " fullword ascii
		$s2 = "Set objCmd = objWShell.Exec(command)" fullword ascii
		$s3 = "Response.Write command & \"<br>\"" fullword ascii
		$s4 = "<form name=\"dns\" method=\"POST\">" fullword ascii

	condition:
		filesize <21KB and all of them
}
