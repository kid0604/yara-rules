rule WaterPamola_javascriptstealer_encode
{
	meta:
		description = "JavaScript stealer using water pamola"
		author = "JPCERT/CC Incident Response Group"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$func1 = ".split('|'),0,{}));"
		$func2 = "return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))"
		$func3 = "RegExp('\\b'+e(c)+'\\b','g'),k[c]);"
		$func4 = "while(c--)if(k[c])"

	condition:
		all of them
}
