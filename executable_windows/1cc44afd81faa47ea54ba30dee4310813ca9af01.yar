import "pe"

rule WannaDecryptor : WannaDecryptor
{
	meta:
		description = "Detection for common strings of WannaDecryptor"
		os = "windows"
		filetype = "executable"

	strings:
		$id1 = "taskdl.exe"
		$id2 = "taskse.exe"
		$id3 = "r.wnry"
		$id4 = "s.wnry"
		$id5 = "t.wnry"
		$id6 = "u.wnry"
		$id7 = "msg/m_"

	condition:
		3 of them
}
