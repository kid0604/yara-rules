rule amasty_biz_js
{
	meta:
		description = "Detects suspicious JavaScript string in Amasty Biz files"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$ = "t_p#0.qlb#0.#1Blsjj#1@#.?#.?dslargml#0.qr_pr#06#07#5@#.?#0"

	condition:
		any of them
}
