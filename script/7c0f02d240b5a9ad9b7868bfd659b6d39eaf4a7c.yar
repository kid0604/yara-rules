rule elmaliseker_alt_1
{
	meta:
		description = "Webshells Auto-generated - file elmaliseker.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "ccf48af0c8c09bbd038e610a49c9862e"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s0 = "javascript:Command('Download'"
		$s5 = "zombie_array=array("

	condition:
		all of them
}
