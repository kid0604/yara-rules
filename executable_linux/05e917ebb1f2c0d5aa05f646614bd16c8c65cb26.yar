rule CN_Honker_mempodipper2_6
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file mempodipper2.6.39"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "ba2c79911fe48660898039591e1742b3f1a9e923"
		os = "linux"
		filetype = "executable"

	strings:
		$s0 = "objdump -d /bin/su|grep '<exit@plt>'|head -n 1|cut -d ' ' -f 1|sed" ascii

	condition:
		filesize <30KB and all of them
}
