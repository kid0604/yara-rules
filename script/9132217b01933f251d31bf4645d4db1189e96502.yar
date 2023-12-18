rule MAL_Python_Backdoor_Script_Nov23
{
	meta:
		author = "X__Junior"
		description = "Detects a trojan (written in Python) that communicates with c2 - was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
		date = "2023-11-23"
		hash1 = "906602ea3c887af67bcb4531bbbb459d7c24a2efcb866bcb1e3b028a51f12ae6"
		score = 80
		id = "861f9ce3-3c54-5c56-b50b-2b7536783f6e"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "port = 443 if \"https\"" ascii
		$s2 = "winrm.Session basic error" ascii
		$s3 = "Windwoscmd.run_cmd(str(cmd))" ascii

	condition:
		filesize <50KB and all of them
}
