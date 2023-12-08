rule apt_CN_Tetris_JS_advanced_1
{
	meta:
		author = "@imp0rtp3 (modified by Florian Roth)"
		description = "Unique code from Jetriz, Swid & Jeniva of the Tetris framework"
		reference = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"
		date = "2020-09-06"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$a1 = "var a0_0x"
		$b1 = "a0_0x" ascii
		$cx1 = "))),function(){try{var _0x"
		$cx2 = "=window)||void 0x0===_0x"
		$cx3 = "){if(opener&&void 0x0!==opener["
		$cx4 = "String['fromCharCode'](0x"
		$e1 = "')](__p__)"

	condition:
		$a1 at 0 or ( filesize <1000KB and (#b1>300 or #e1>1 or 2 of ($cx*)))
}
