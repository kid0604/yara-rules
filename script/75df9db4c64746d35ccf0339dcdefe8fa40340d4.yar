rule webshell_ASP_zehir4
{
	meta:
		description = "Web Shell - file zehir4.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "7f4e12e159360743ec016273c3b9108c"
		os = "windows"
		filetype = "script"

	strings:
		$s9 = "Response.Write \"<a href='\"&dosyaPath&\"?status=7&Path=\"&Path&\"/"

	condition:
		all of them
}
