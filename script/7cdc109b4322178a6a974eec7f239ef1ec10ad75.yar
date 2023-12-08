import "pe"

rule MALWARE_Linux_XORDDoS
{
	meta:
		author = "ditekSHen"
		description = "Detects XORDDoS"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "for i in `cat /proc/net/dev|grep :|awk -F: {'print $1'}`; do ifconfig $i up& done" fullword ascii
		$s2 = "cp /lib/libudev.so /lib/libudev.so.6" fullword ascii
		$s3 = "sed -i '/\\/etc\\/cron.hourly\\/gcc.sh/d' /etc/crontab && echo '*/3 * * * * root /etc/cron.hourly/gcc.sh' >> /etc/crontab" fullword ascii
		$s4 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; TencentTraveler ; .NET CLR 1.1.4322)" fullword ascii

	condition:
		uint32(0)==0x464c457f and 3 of them
}
