rule _Bitchin_Threads_
{
	meta:
		description = "Auto-generated rule on file =Bitchin Threads=.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "7491b138c1ee5a0d9d141fbfd1f0071b"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "DarKPaiN"
		$s1 = "=BITCHIN THREADS"

	condition:
		all of them
}
