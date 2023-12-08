private rule is__LinuxHttpsdStrings
{
	meta:
		description = "Strings of ELF Linux/Httpsd (backdoor, downloader, remote command execution)"
		ref1 = "https://imgur.com/a/8mFGk"
		ref2 = "https://otx.alienvault.com/pulse/5a49115f93199b171b90a212"
		ref3 = "https://misppriv.circl.lu/events/view/9952"
		author = "unixfreaxjp"
		org = "MalwareMustDie"
		date = "2018-01-02"
		sha256 = "dd1266561fe7fcd54d1eb17efbbb6babaa9c1f44b36cef6e06052e22ce275ccd"
		sha256 = "1b3718698fae20b63fbe6ab32411a02b0b08625f95014e03301b49afaee9d559"
		os = "linux"
		filetype = "executable"

	strings:
		$st01 = "k.conectionapis.com" fullword nocase wide ascii
		$st02 = "key=%s&host_name=%s&cpu_count=%d&os_type=%s&core_count=%s" fullword nocase wide ascii
		$st03 = "id=%d&result=%s" fullword nocase wide ascii
		$st04 = "rtime" fullword nocase wide ascii
		$st05 = "down" fullword nocase wide ascii
		$st06 = "cmd" fullword nocase wide ascii
		$st07 = "0 */6 * * * root" fullword nocase wide ascii
		$st08 = "/etc/cron.d/httpsd" fullword nocase wide ascii
		$st09 = "cat /proc/cpuinfo |grep processor|wc -l" fullword nocase wide ascii
		$st10 = "k.conectionapis.com" fullword nocase wide ascii
		$st11 = "/api" fullword nocase wide ascii
		$st12 = "/tmp/.httpslog" fullword nocase wide ascii
		$st13 = "/bin/.httpsd" fullword nocase wide ascii
		$st14 = "/tmp/.httpsd" fullword nocase wide ascii
		$st15 = "/tmp/.httpspid" fullword nocase wide ascii
		$st16 = "/tmp/.httpskey" fullword nocase wide ascii

	condition:
		all of them
}
