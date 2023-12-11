rule generic_javascript_obfuscation
{
	meta:
		author = "Josh Berry"
		date = "2016-06-26"
		description = "JavaScript Obfuscation Detection"
		sample_filetype = "js-html"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$string0 = /eval\(([\s]+)?(unescape|atob)\(/ nocase
		$string1 = /var([\s]+)?([a-zA-Z_$])+([a-zA-Z0-9_$]+)?([\s]+)?=([\s]+)?\[([\s]+)?\"\\x[0-9a-fA-F]+/ nocase
		$string2 = /var([\s]+)?([a-zA-Z_$])+([a-zA-Z0-9_$]+)?([\s]+)?=([\s]+)?eval;/

	condition:
		any of them
}
