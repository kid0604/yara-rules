rule SUSP_obfuscated_JS_obfuscatorio : HIGHVOL
{
	meta:
		author = "@imp0rtp3"
		description = "Detects JS obfuscation done by the js obfuscator (often malicious)"
		reference = "https://obfuscator.io"
		date = "2021-08-25"
		score = 50
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$a1 = "var a0_0x"
		$c1 = "))),function(){try{var _0x"
		$c2 = "=Function('return\\x20(function()\\x20'+'{}.constructor(\\x22return\\x20this\\x22)(\\x20)'+');');"
		$c3 = "['atob']=function("
		$c4 = ")['replace'](/=+$/,'');var"
		$c5 = "return!![]"
		$c6 = "'{}.constructor(\\x22return\\\x20this\\x22)(\\x20)'"
		$c7 = "{}.constructor(\x22return\x20this\x22)(\x20)" base64
		$c8 = "while(!![])"
		$c9 = "while (!![])"
		$d1 = /(parseInt\(_0x([a-f0-9]{2}){2,4}\(0x[a-f0-9]{1,5}\)\)\/0x[a-f0-9]{1,2}\)?(\+|\*\()\-?){6}/

	condition:
		$a1 at 0 or ( filesize <1000000 and (3 of ($c*) or $d1))
}
