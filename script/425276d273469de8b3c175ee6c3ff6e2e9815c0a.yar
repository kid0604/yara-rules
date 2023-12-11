rule Trafficanalyzer_js
{
	meta:
		description = "Detects JavaScript code used for traffic analysis"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "z=x['length'];for(i=0;i<z;i++){y+=String['fromCharCode'](x['charCodeAt'](i)-10) }w=this['unescape'](y);this['eval'](w);"

	condition:
		any of them
}
