rule webshell_asp_1d
{
	meta:
		description = "Web Shell - file 1d.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "fad7504ca8a55d4453e552621f81563c"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "+9JkskOfKhUxZJPL~\\(mD^W~[,{@#@&EO"

	condition:
		all of them
}
