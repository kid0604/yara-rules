rule asp_proxy : webshell
{
	meta:
		description = "Laudanum Injector Tools - file proxy.asp"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "51e97040d1737618b1775578a772fa6c5a31afd8"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "'response.write \"<br/>  -value:\" & request.querystring(key)(j)" fullword ascii
		$s2 = "q = q & \"&\" & key & \"=\" & request.querystring(key)(j)" fullword ascii
		$s3 = "for each i in Split(http.getAllResponseHeaders, vbLf)" fullword ascii
		$s4 = "'urlquery = mid(urltemp, instr(urltemp, \"?\") + 1)" fullword ascii
		$s5 = "s = urlscheme & urlhost & urlport & urlpath" fullword ascii
		$s6 = "Set http = Server.CreateObject(\"Microsoft.XMLHTTP\")" fullword ascii

	condition:
		filesize <50KB and all of them
}
