rule webshell_DarkBlade1_3_asp_indexx
{
	meta:
		description = "Web Shell - file indexx.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "b7f46693648f534c2ca78e3f21685707"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s3 = "Const strs_toTransform=\"command|Radmin|NTAuThenabled|FilterIp|IISSample|PageCou"

	condition:
		all of them
}
